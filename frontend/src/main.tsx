import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "./styles.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AppRoutes, makeQueryClient, Providers } from "./App";

const client = makeQueryClient();

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <Providers client={client}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </Providers>
  </StrictMode>,
);
