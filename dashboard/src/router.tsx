import { createBrowserRouter, useOutletContext } from "react-router";
import { Layout, type LayoutContext } from "./components/Layout";
import { Timeline } from "./components/Timeline";
import { Panel } from "./components/ui";
import { AccessPointView } from "./views/AccessPointView";
import { AlertsView } from "./views/AlertsView";
import { OverviewView } from "./views/OverviewView";
import { SystemView } from "./views/SystemView";

// Every view has its own URL, so a selected alert or AP can be bookmarked or shared.
export const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <OverviewView /> },
      { path: "alerts/:alertId?", element: <AlertsView /> },
      { path: "aps/:bssid?", element: <AccessPointView /> },
      { path: "activity", element: <ActivityView /> },
      { path: "system", element: <SystemView /> },
    ],
  },
]);

function ActivityView() {
  const { timeline } = useOutletContext<LayoutContext>();
  return (
    <Panel title="Activity" sub="Evidence and alert changes as they are recorded.">
      <Timeline entries={timeline} newestFirst />
    </Panel>
  );
}
