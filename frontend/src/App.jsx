import React, { useState, useEffect } from 'react';
import { auth } from './auth.js';
import LoginPage from './pages/LoginPage.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import DomainsPage from './pages/DomainsPage.jsx';
import ScansPage from './pages/ScansPage.jsx';
import ScanStartPage from './pages/ScanStartPage.jsx';
import ScanDetailPage from './pages/ScanDetailPage.jsx';
import FindingsPage from './pages/FindingsPage.jsx';
import WorkflowsPage from './pages/WorkflowsPage.jsx';
import WorkflowDetailPage from './pages/WorkflowDetailPage.jsx';
import InsightsPage from './pages/InsightsPage.jsx';

function NotFound() {
  return <div className="p-8 text-body">404 - Page not found</div>;
}

function navigate(path) {
  window.history.pushState({}, '', path);
  window.dispatchEvent(new Event('popstate'));
}

export { navigate };

export default function App() {
  const [path, setPath] = useState(window.location.pathname);

  useEffect(() => {
    const handler = () => setPath(window.location.pathname);
    window.addEventListener('popstate', handler);
    return () => window.removeEventListener('popstate', handler);
  }, []);

  // Guard: redirect to /login if no token (replace avoids adding to history)
  if (path !== '/login' && !auth.isLoggedIn()) {
    window.location.replace('/login');
    return null;
  }

  if (path === '/login') return <LoginPage />;
  if (path === '/') return <DashboardPage />;
  if (path === '/domains') return <DomainsPage />;
  if (path === '/scans') return <ScansPage />;
  if (path === '/scans/start') return <ScanStartPage />;
  if (path.startsWith('/scans/') && path.length > 8) return <ScanDetailPage />;
  if (path === '/findings') return <FindingsPage />;
  if (path === '/workflows') return <WorkflowsPage />;
  if (path.startsWith('/workflows/') && path.length > 11) return <WorkflowDetailPage />;
  if (path === '/insights') return <InsightsPage />;
  return <NotFound />;
}
