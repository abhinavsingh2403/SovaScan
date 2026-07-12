import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Findings from './pages/Findings';
import Scan from './pages/Scan';
import Compliance from './pages/Compliance';
import Settings from './pages/Settings';
import Profile from './pages/Profile';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/profile" element={<Profile />} />
      </Routes>
    </Layout>
  );
}

export default App;
