import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Findings from './pages/Findings';
import Scan from './pages/Scan';
import Compliance from './pages/Compliance';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/compliance" element={<Compliance />} />
      </Routes>
    </Layout>
  );
}

export default App;
