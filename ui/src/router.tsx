// Code-based route tree (no file-based codegen — kept simple and fully
// readable in one file, which matters more than convention for a small,
// fixed set of routes in a template). `Layout` is the root route's
// component, so the sidebar/topbar shell wraps every page via <Outlet/>.
import { createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import Layout from "./components/Layout";
import AccountDetailPage from "./pages/AccountDetail";
import AccountsPage from "./pages/Accounts";
import ActivityLogPage from "./pages/ActivityLog";
import CertificateAuthorityPage from "./pages/CertificateAuthority";
import CertificateDetailPage from "./pages/CertificateDetail";
import CertificatesPage from "./pages/Certificates";
import ComponentsPage from "./pages/Components";
import DashboardPage from "./pages/Dashboard";
import NotFoundPage from "./pages/NotFound";
import OrderDetailPage from "./pages/OrderDetail";
import OrdersPage from "./pages/Orders";
import SettingsPage from "./pages/Settings";

const rootRoute = createRootRoute({
  component: Layout,
});

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
});

const certificatesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/certificates",
  component: CertificatesPage,
});

const certificateDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/certificates/$certificateId",
  component: CertificateDetailPage,
});

const ordersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/orders",
  component: OrdersPage,
});

const orderDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/orders/$orderId",
  component: OrderDetailPage,
});

const accountsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/accounts",
  component: AccountsPage,
});

const accountDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/accounts/$accountId",
  component: AccountDetailPage,
});

const activityLogRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/activity",
  component: ActivityLogPage,
});

const certificateAuthorityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/certificate-authority",
  component: CertificateAuthorityPage,
});

const componentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/components",
  component: ComponentsPage,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
});

const routeTree = rootRoute.addChildren([
  dashboardRoute,
  certificatesRoute,
  certificateDetailRoute,
  ordersRoute,
  orderDetailRoute,
  accountsRoute,
  accountDetailRoute,
  activityLogRoute,
  certificateAuthorityRoute,
  componentsRoute,
  settingsRoute,
]);

export const router = createRouter({
  routeTree,
  defaultNotFoundComponent: NotFoundPage,
});

// Registers the concrete router type globally so <Link to="…"> and
// useNavigate() are type-checked against the real route paths above.
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
