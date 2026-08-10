import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import {
  Link,
  Outlet,
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
  useRouterState,
} from "@tanstack/react-router";

import { NotSignedIn, api } from "./api";
import { Devices } from "./Devices";
import { Keys } from "./Keys";
import { Activate } from "./Activate";
import "./styles.css";

function SignIn() {
  return (
    <div className="signin">
      <h1>smol</h1>
      <p className="meta">a small mesh, and a console for it</p>
      <a href="/auth/google">Sign in with Google</a>
    </div>
  );
}

function Shell() {
  const path = useRouterState({ select: (state) => state.location.pathname });

  const { data, isPending, error } = useQuery({
    queryKey: ["me"],
    queryFn: api.me,
    retry: (count, error) => !(error instanceof NotSignedIn) && count < 2,
  });

  if (isPending) {
    return <div className="shell meta">loading…</div>;
  }

  if (error instanceof NotSignedIn) {
    return <SignIn />;
  }

  if (error) {
    return <div className="shell meta">could not reach the control server: {String(error)}</div>;
  }

  return (
    <div className="shell">
      <header>
        <div>
          <h1>smol</h1>
          <div className="meta">
            {data.email} · network <code>{data.subnet}</code>
          </div>
        </div>
        <div className="row">
          <nav>
            <Link to="/" className={path === "/" ? "active" : ""}>
              Devices
            </Link>
            <Link to="/keys" className={path === "/keys" ? "active" : ""}>
              Auth keys
            </Link>
          </nav>
          <form method="post" action="/auth/logout">
            <button type="submit">Sign out</button>
          </form>
        </div>
      </header>
      <Outlet />
    </div>
  );
}

const root = createRootRoute({ component: Shell });

const devices = createRoute({ getParentRoute: () => root, path: "/", component: Devices });
const keys = createRoute({ getParentRoute: () => root, path: "/keys", component: Keys });
const activate = createRoute({
  getParentRoute: () => root,
  path: "/activate",
  component: Activate,
});

const router = createRouter({ routeTree: root.addChildren([devices, keys, activate]) });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const queries = new QueryClient({
  defaultOptions: { queries: { staleTime: 5_000, refetchOnWindowFocus: true } },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queries}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
