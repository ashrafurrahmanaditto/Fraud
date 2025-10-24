import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import UrlShortener from './components/UrlShortener'
import AdminDashboard from './components/AdminDashboard'
import RedirectHandler from './components/RedirectHandler'
import './App.css'

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Toaster position="top-right" />
        
        <Routes>
          <Route path="/" element={<UrlShortener />} />
          <Route path="/admin" element={<AdminDashboard />} />
          <Route path="/:shortCode" element={<RedirectHandler />} />
        </Routes>
      </div>
    </Router>
  )
}

export default App
