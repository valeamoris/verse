import React from 'react'
import { createRoot } from 'react-dom/client'
import SafeAppsSDK from '@safe-global/safe-apps-sdk'
import { App } from './App'
import './styles.css'

const sdk = new SafeAppsSDK()

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App sdk={sdk} />
  </React.StrictMode>,
)
