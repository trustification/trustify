import React from "react";
import ReactDOM from "react-dom/client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

import ENV from "@app/env";
import App from "@app/App";
import reportWebVitals from "@app/reportWebVitals";

import dayjs from "dayjs";
import isSameOrBefore from "dayjs/plugin/isSameOrBefore";
import utc from "dayjs/plugin/utc";
import timezone from "dayjs/plugin/timezone";
import customParseFormat from "dayjs/plugin/customParseFormat";
import arraySupport from "dayjs/plugin/arraySupport";

import { OidcProvider } from "@app/components/OidcProvider";

dayjs.extend(utc);
dayjs.extend(timezone);
dayjs.extend(customParseFormat);
dayjs.extend(isSameOrBefore);
dayjs.extend(arraySupport);

const queryClient = new QueryClient();

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement
);

const renderApp = () => {
  return root.render(
    <React.StrictMode>
      <OidcProvider>
        <QueryClientProvider client={queryClient}>
          <App />
          <ReactQueryDevtools initialIsOpen={false} />
        </QueryClientProvider>
      </OidcProvider>
    </React.StrictMode>
  );
};

if (ENV.NODE_ENV === "development") {
  import("./mocks/browser").then((browserMocks) => {
    if (browserMocks.config.enabled) {
      browserMocks.worker.start();
    }
    renderApp();
  });
} else {
  renderApp();
}

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
