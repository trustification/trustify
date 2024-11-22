variable "cluster-vpc-id" {
  type        = string
  description = "The VPC ID of the cluster. Used to connect the RDS instance to the same subnet."
}

data "aws_vpc" "cluster" {
  id = var.cluster-vpc-id
}

data "aws_subnets" "cluster-private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.cluster.id]
  }
  tags = {
    "kubernetes.io/role/internal-elb" = ""
  }
}

resource "aws_db_subnet_group" "database" {
  name       = "database-${var.environment}"
  subnet_ids = data.aws_subnets.cluster-private.ids
}

resource "aws_security_group" "database" {
  name   = "trustify-postgresql-${var.environment}"
  vpc_id = data.aws_vpc.cluster.id
}

resource "aws_security_group_rule" "allow-postgres" {
  protocol          = "TCP"
  security_group_id = aws_security_group.database.id
  from_port         = 5432
  to_port           = 5432
  type              = "ingress"
  cidr_blocks       = data.aws_vpc.cluster.cidr_block != "" ? [data.aws_vpc.cluster.cidr_block] : []
  ipv6_cidr_blocks  = data.aws_vpc.cluster.ipv6_cidr_block != "" ? [data.aws_vpc.cluster.ipv6_cidr_block] : []
}

variable "db-master-user" {
  type        = string
  default     = "postgres"
  description = "Username of the master user of the database"
}

variable "db-user" {
  type        = string
  default     = "trustify"
  description = "Username of the trustify user of the database"
}

locals {
  # name of the database:
  # > * Must contain 1 to 63 letters, numbers, or underscores.
  # > * Must begin with a letter. Subsequent characters can be letters, underscores, or digits (0-9).
  # > * Can't be a word reserved by the specified database engine
  db-name = "trustify_${var.environment}"
}

resource "random_password" "trustify-db-admin-password" {
  length  = 32
  # some special characters are limited
  special = false
}

resource "random_password" "trustify-db-user-password" {
  length  = 32
  # some special characters are limited
  special = false
}

resource "kubernetes_secret" "postgresql-admin-credentials" {
  metadata {
    name      = "postgresql-admin-credentials"
    namespace = var.namespace
  }

  data = {
    "db.user"     = var.db-master-user
    "db.password" = random_password.trustify-db-admin-password.result
    "db.name"     = "postgres"
    "db.port"     = aws_db_instance.trustify.port
    "db.host"     = aws_db_instance.trustify.address
  }

  type = "Opaque"
}

resource "kubernetes_secret" "postgresql-credentials" {
  metadata {
    name      = "postgresql-credentials"
    namespace = var.namespace
  }

  data = {
    "db.user"     = var.db-user
    "db.password" = random_password.trustify-db-user-password.result
    "db.name"     = local.db-name
    "db.port"     = aws_db_instance.trustify.port
    "db.host"     = aws_db_instance.trustify.address
  }

  type = "Opaque"
}

resource "aws_db_instance" "trustify" {

  db_subnet_group_name = aws_db_subnet_group.database.name

  apply_immediately = true

  allocated_storage     = 10
  max_allocated_storage = 100

  db_name             = "postgres"
  engine              = "postgres"
  engine_version      = "17.2"
  instance_class      = "db.m7g.large"
  username            = var.db-master-user
  password            = random_password.trustify-db-admin-password.result
  ca_cert_identifier  = "rds-ca-rsa4096-g1"
  skip_final_snapshot = true

  availability_zone = var.availability-zone
}
