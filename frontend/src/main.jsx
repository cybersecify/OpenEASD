import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App.jsx';
import { Toaster } from './components/ui/sonner.jsx';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
    <Toaster theme="dark" position="top-right" richColors />
  </React.StrictMode>
);
