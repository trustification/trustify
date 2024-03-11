import React from "react";
import { Link } from "react-router-dom";

import {
  Breadcrumb,
  BreadcrumbItem,
  PageSection,
  Text,
  TextContent,
} from "@patternfly/react-core";

import DetailsPage from "@patternfly/react-component-groups/dist/dynamic/DetailsPage";

import { PathParam, useRouteParams } from "@app/Routes";
import { useFetchPackageById } from "@app/queries/packages";

import { LoadingWrapper } from "@app/components/LoadingWrapper";
import { RelatedCVEs } from "./related-cves";
import { RelatedSBOMs } from "./related-sboms";

export const PackageDetails: React.FC = () => {
  const packageId = useRouteParams(PathParam.PACKAGE_ID);

  const {
    pkg,
    isFetching: isFetchingSbom,
    fetchError: fetchErrorSbom,
  } = useFetchPackageById(packageId);

  return (
    <>
      <PageSection variant="light">
        <DetailsPage
          breadcrumbs={
            <Breadcrumb>
              <BreadcrumbItem key="packages">
                <Link to="/packages">Packages</Link>
              </BreadcrumbItem>
              <BreadcrumbItem to="#" isActive>
                Package details
              </BreadcrumbItem>
            </Breadcrumb>
          }
          pageHeading={{
            title: pkg?.name ?? packageId ?? "",
            iconAfterTitle: pkg ? (
              <TextContent>
                <Text component="pre">{`version: ${pkg.version}`}</Text>
              </TextContent>
            ) : undefined,
            label: pkg
              ? {
                  children: pkg ? `type=${pkg.type}` : "",
                  isCompact: true,
                }
              : undefined,
          }}
          actionButtons={[]}
          tabs={[
            {
              eventKey: "cves",
              title: "CVEs",
              children: (
                <div className="pf-v5-u-m-md">
                  <LoadingWrapper
                    isFetching={isFetchingSbom}
                    fetchError={fetchErrorSbom}
                  >
                    {pkg && <RelatedCVEs cves={pkg?.related_cves || []} />}
                  </LoadingWrapper>
                </div>
              ),
            },
            {
              eventKey: "sboms",
              title: "SBOMs",
              children: (
                <div className="pf-v5-u-m-md">
                  <LoadingWrapper
                    isFetching={isFetchingSbom}
                    fetchError={fetchErrorSbom}
                  >
                    {pkg && <RelatedSBOMs sboms={pkg?.related_sboms} />}
                  </LoadingWrapper>
                </div>
              ),
            },
          ]}
        />
      </PageSection>
    </>
  );
};
