import React from 'react';
import { createBrowserRouter, Navigate, Outlet } from 'react-router-dom';
import { auth } from './auth.js';

import LoginPage from './pages/LoginPage.jsx';
import SetupPage from './pages/SetupPage.jsx';
import ChangePasswordPage from './pages/ChangePasswordPage.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import DomainsPage from './pages/DomainsPage.jsx';
import ScansPage from './pages/ScansPage.jsx';
import ScanStartPage from './pages/ScanStartPage.jsx';
import ScanDetailPage from './pages/ScanDetailPage.jsx';
import FindingsPage from './pages/FindingsPage.jsx';
import WorkflowsPage from './pages/WorkflowsPage.jsx';
import WorkflowDetailPage from './pages/WorkflowDetailPage.jsx';
import InsightsPage from './pages/InsightsPage.jsx';
import NotificationsPage from './pages/NotificationsPage.jsx';

function NotFound() {
  return <div className="p-8 text-body">404 - Page not found</div>;
}

function ProtectedRoute() {
  if (!auth.isLoggedIn()) return <Navigate to="/login" replace />;
  return <Outlet />;
}

export const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  { path: '/setup', element: <SetupPage /> },
  {
    element: <ProtectedRoute />,
    children: [
      { path: '/', element: <DashboardPage /> },
      { path: '/change-password', element: <ChangePasswordPage /> },
      { path: '/domains', element: <DomainsPage /> },
      { path: '/scans', element: <ScansPage /> },
      { path: '/scans/start', element: <ScanStartPage /> },
      { path: '/scans/:uuid', element: <ScanDetailPage /> },
      { path: '/findings', element: <FindingsPage /> },
      { path: '/workflows', element: <WorkflowsPage /> },
      { path: '/workflows/:id', element: <WorkflowDetailPage /> },
      { path: '/insights', element: <InsightsPage /> },
      { path: '/notifications', element: <NotificationsPage /> },
    ],
  },
  { path: '*', element: <NotFound /> },
]);
