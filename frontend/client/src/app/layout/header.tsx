import React, { useReducer, useState } from "react";
import { useAuth } from "react-oidc-context";
import { useNavigate } from "react-router-dom";

import {
  Avatar,
  Brand,
  Button,
  ButtonVariant,
  Dropdown,
  DropdownItem,
  DropdownList,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadMain,
  MastheadToggle,
  MenuToggle,
  MenuToggleElement,
  PageToggleButton,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
} from "@patternfly/react-core";

import BarsIcon from "@patternfly/react-icons/dist/js/icons/bars-icon";
import QuestionCircleIcon from "@patternfly/react-icons/dist/esm/icons/question-circle-icon";
import EllipsisVIcon from "@patternfly/react-icons/dist/esm/icons/ellipsis-v-icon";
import HelpIcon from "@patternfly/react-icons/dist/esm/icons/help-icon";

import { useLocalStorage } from "@app/hooks/useStorage";
import { isAuthRequired } from "@app/Constants";

import { AboutApp } from "./about";
import imgAvatar from "../images/avatar.svg";
import useBranding from "@app/hooks/useBranding";

export const HeaderApp: React.FC = () => {
  const {
    masthead: { leftBrand, leftTitle, rightBrand },
  } = useBranding();

  const auth = (isAuthRequired && useAuth()) || undefined;

  const navigate = useNavigate();

  const [isAboutOpen, toggleIsAboutOpen] = useReducer((state) => !state, false);
  const [isLangDropdownOpen, setIsLangDropdownOpen] = useState(false);
  const [isKebabDropdownOpen, setIsKebabDropdownOpen] = useState(false);
  const [isUserDropdownOpen, setIsUserDropdownOpen] = useState(false);

  const [lang, setLang] = useLocalStorage({ key: "lang", defaultValue: "es" });

  const kebabDropdownItems = (
    <>
      <DropdownItem key="about" onClick={toggleIsAboutOpen}>
        <HelpIcon /> About
      </DropdownItem>
    </>
  );

  const onKebabDropdownToggle = () => {
    setIsKebabDropdownOpen(!isKebabDropdownOpen);
  };

  const onKebabDropdownSelect = () => {
    setIsKebabDropdownOpen(!isKebabDropdownOpen);
  };

  return (
    <>
      <AboutApp isOpen={isAboutOpen} onClose={toggleIsAboutOpen} />

      <Masthead>
        <MastheadToggle>
          <PageToggleButton variant="plain" aria-label="Global navigation">
            <BarsIcon />
          </PageToggleButton>
        </MastheadToggle>
        <MastheadMain>
          <MastheadBrand>
            {leftBrand ? (
              <Brand
                src={leftBrand.src}
                alt={leftBrand.alt}
                heights={{ default: leftBrand.height }}
              />
            ) : null}
          </MastheadBrand>
        </MastheadMain>
        <MastheadContent>
          <Toolbar id="toolbar" isFullHeight isStatic>
            <ToolbarContent>
              <ToolbarGroup
                variant="icon-button-group"
                align={{ default: "alignRight" }}
                spacer={{ default: "spacerNone", md: "spacerMd" }}
              >
                <ToolbarGroup
                  variant="icon-button-group"
                  visibility={{ default: "hidden", lg: "visible" }}
                >
                  <ToolbarItem>
                    <Button
                      aria-label="About"
                      variant={ButtonVariant.plain}
                      icon={<QuestionCircleIcon />}
                      onClick={toggleIsAboutOpen}
                    />
                  </ToolbarItem>
                </ToolbarGroup>
                <ToolbarItem
                  visibility={{
                    default: "hidden",
                    md: "visible",
                    lg: "hidden",
                  }}
                >
                  <Dropdown
                    isOpen={isKebabDropdownOpen}
                    onSelect={onKebabDropdownSelect}
                    onOpenChange={(isOpen: boolean) =>
                      setIsKebabDropdownOpen(isOpen)
                    }
                    popperProps={{ position: "right" }}
                    toggle={(toggleRef: React.Ref<MenuToggleElement>) => (
                      <MenuToggle
                        ref={toggleRef}
                        onClick={onKebabDropdownToggle}
                        isExpanded={isKebabDropdownOpen}
                        variant="plain"
                        aria-label="About"
                      >
                        <EllipsisVIcon aria-hidden="true" />
                      </MenuToggle>
                    )}
                  >
                    <DropdownList>{kebabDropdownItems}</DropdownList>
                  </Dropdown>
                </ToolbarItem>
                {auth && (
                  <ToolbarItem
                    visibility={{ default: "hidden", md: "visible" }}
                  >
                    <Dropdown
                      isOpen={isUserDropdownOpen}
                      onSelect={() => setIsUserDropdownOpen(false)}
                      onOpenChange={(isOpen: boolean) =>
                        setIsUserDropdownOpen(isOpen)
                      }
                      popperProps={{ position: "right" }}
                      toggle={(toggleRef: React.Ref<MenuToggleElement>) => (
                        <MenuToggle
                          ref={toggleRef}
                          onClick={() =>
                            setIsUserDropdownOpen(!isUserDropdownOpen)
                          }
                          isFullHeight
                          isExpanded={isUserDropdownOpen}
                          icon={<Avatar src={imgAvatar} alt="" />}
                        >
                          {auth.user?.profile.preferred_username}
                        </MenuToggle>
                      )}
                    >
                      <DropdownList>
                        <DropdownItem
                          key="logout"
                          onClick={() => {
                            auth
                              .signoutRedirect()
                              .then(() => {})
                              .catch((err) => {
                                console.error("Logout failed:", err);
                                navigate("/");
                              });
                          }}
                        >
                          Logout
                        </DropdownItem>
                      </DropdownList>
                    </Dropdown>
                  </ToolbarItem>
                )}
              </ToolbarGroup>
            </ToolbarContent>
          </Toolbar>
        </MastheadContent>
      </Masthead>
    </>
  );
};
