import React from "react";
import { Link } from "react-router-dom";

import {
  Breadcrumb,
  BreadcrumbItem,
  PageSection,
} from "@patternfly/react-core";

import DetailsPage from "@patternfly/react-component-groups/dist/dynamic/DetailsPage";
import DownloadIcon from "@patternfly/react-icons/dist/esm/icons/download-icon";

import { PathParam, useRouteParams } from "@app/Routes";

import { LoadingWrapper } from "@app/components/LoadingWrapper";
import { useDownload } from "@app/hooks/useDownload";
import { useFetchSBOMById } from "@app/queries/sboms";

import { DependencyAnalytics } from "./dependency-analytics";
import { Overview } from "./overview";
import { Packages } from "./packages";
import { Source } from "./source";
import { CVEs } from "./cves";

export const SbomDetails: React.FC = () => {
  const sbomId = useRouteParams(PathParam.SBOM_ID);

  const { sbom, isFetching, fetchError } = useFetchSBOMById(sbomId);

  const { downloadSBOM } = useDownload();

  return (
    <>
      <PageSection variant="light">
        <DetailsPage
          breadcrumbs={
            <Breadcrumb>
              <BreadcrumbItem key="advisories">
                <Link to="/sboms">SBOMs</Link>
              </BreadcrumbItem>
              <BreadcrumbItem to="#" isActive>
                SBOM details
              </BreadcrumbItem>
            </Breadcrumb>
          }
          pageHeading={{
            title: sbom?.name ?? sbomId ?? "",
            label: sbom
              ? {
                  children: sbom.type,
                  isCompact: true,
                  color: "blue",
                }
              : undefined,
          }}
          actionButtons={[
            {
              children: (
                <>
                  <DownloadIcon /> Download
                </>
              ),
              onClick: () => {
                if (sbomId) {
                  downloadSBOM(sbomId);
                }
              },
              variant: "secondary",
            },
          ]}
          tabs={[
            {
              eventKey: "overview",
              title: "Overview",
              children: (
                <div className="pf-v5-u-m-md">
                  <LoadingWrapper
                    isFetching={isFetching}
                    fetchError={fetchError}
                  >
                    {sbom && <Overview sbom={sbom} />}
                  </LoadingWrapper>
                </div>
              ),
            },
            {
              eventKey: "cves",
              title: "CVEs",
              children: (
                <div className="pf-v5-u-m-md">
                  {sbomId && <CVEs sbomId={sbomId} />}
                </div>
              ),
            },
            {
              eventKey: "packages",
              title: "Packages",
              children: (
                <div className="pf-v5-u-m-md">
                  {sbomId && <Packages sbomId={sbomId} />}
                </div>
              ),
            },
            {
              eventKey: "source",
              title: "Source",
              children: (
                <div className="pf-v5-u-m-md">
                  {sbomId && <Source sbomId={sbomId} />}
                </div>
              ),
            },
            {
              eventKey: "dependency-analytics",
              title: "Dependency analytics",
              children: (
                <div className="pf-v5-u-m-md">
                  {sbomId && <DependencyAnalytics sbomId={sbomId} />}
                </div>
              ),
            },
          ]}
        />
      </PageSection>
    </>
  );
};
