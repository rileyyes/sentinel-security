import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";
import Layout from "./components/Layout";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import InvestigateSoftware from "./pages/InvestigateSoftware";
import SecureSoftware from "./pages/SecureSoftware";
import InvestigationDetail from "./pages/InvestigationDetail";
import Settings from "./pages/Settings";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/investigate" element={<InvestigateSoftware />} />
          <Route path="/secure" element={<SecureSoftware />} />
          <Route path="/investigations/:id" element={<InvestigationDetail />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
