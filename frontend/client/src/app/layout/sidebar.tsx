import React from "react";
import { NavLink } from "react-router-dom";

import { Nav, NavList, PageSidebar } from "@patternfly/react-core";
import { css } from "@patternfly/react-styles";

import { LayoutTheme } from "./layout-constants";

const LINK_CLASS = "pf-v5-c-nav__link";
const ACTIVE_LINK_CLASS = "pf-m-current";

export const SidebarApp: React.FC = () => {
  const renderPageNav = () => {
    return (
      <Nav id="nav-sidebar" aria-label="Nav" theme={LayoutTheme}>
        <NavList>
          <li className="pf-v5-c-nav__item">
            <NavLink
              to="/"
              className={({ isActive }) => {
                return css(LINK_CLASS, isActive ? ACTIVE_LINK_CLASS : "");
              }}
            >
              Dashboard
            </NavLink>
          </li>
          <li className="pf-v5-c-nav__item">
            <NavLink
              to="/sboms"
              className={({ isActive }) => {
                return css(LINK_CLASS, isActive ? ACTIVE_LINK_CLASS : "");
              }}
            >
              SBOMs
            </NavLink>
          </li>
          <li className="pf-v5-c-nav__item">
            <NavLink
              to="/cves"
              className={({ isActive }) => {
                return css(LINK_CLASS, isActive ? ACTIVE_LINK_CLASS : "");
              }}
            >
              CVEs
            </NavLink>
          </li>
          <li className="pf-v5-c-nav__item">
            <NavLink
              to="/packages"
              className={({ isActive }) => {
                return css(LINK_CLASS, isActive ? ACTIVE_LINK_CLASS : "");
              }}
            >
              Packages
            </NavLink>
          </li>
          <li className="pf-v5-c-nav__item">
            <NavLink
              to="/advisories"
              className={({ isActive }) => {
                return css(LINK_CLASS, isActive ? ACTIVE_LINK_CLASS : "");
              }}
            >
              Advisories
            </NavLink>
          </li>
        </NavList>
      </Nav>
    );
  };

  return <PageSidebar theme={LayoutTheme}>{renderPageNav()}</PageSidebar>;
};
