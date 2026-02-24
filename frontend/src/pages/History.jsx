import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Clock, FileText, AlertCircle, CheckCircle, Loader2, Search } from 'lucide-react';

const API_BASE = "/api";

/**
 * History
 *
 * React component that displays a paginated list of recent analysis tasks,
 * provides a SHA256 search to navigate to a specific task, and shows status
 * indicators for each task.
 *
 * Behavior:
 * - Manages internal state: history (Array), isLoading (boolean), error (string|null),
 *   searchHash (string), isSearching (boolean).
 * - On mount, fetches recent history from `${API_BASE}/history?limit=50` using axios.
 *   - Sets history on success, sets error on failure, and toggles isLoading.
 * - Provides searchByHash() to query `${API_BASE}/result/${searchHash}` and navigate
 *   to `/task/{task_id}` when found; shows an error message if not found.
 * - Helper utilities:
 *   - getStatusIcon(status): returns appropriate status icon JSX for 'completed',
 *     'failed', 'pending'/'processing', or default.
 *   - getStatusBadgeClass(status): returns Tailwind CSS classes for badge colors based
 *     on status.
 *   - formatDate(dateString): formats ISO date strings to a human-readable 'en-US'
 *     date + time string; returns 'N/A' for falsy values.
 *
 * Rendering:
 * - While isLoading: displays a centered spinner.
 * - On error: displays an error panel with message.
 * - Main UI:
 *   - Header with title, description, and a search input (SHA256) + search button.
 *   - Container showing either "No analysis history found." or a table of tasks.
 *   - Each task row shows status badge + icon, filename, SHA256, formatted date,
 *     and a "View Details" button that navigates to `/task/{task_id}`.
 * - The search button is disabled when searchHash is empty or a search is in progress.
 *
 * Expectations / Dependencies:
 * - Uses axios for HTTP requests and useNavigate for client navigation.
 * - Expects task items to include: task_id, status, filename, sha256, created_at.
 * - Date formatting uses Intl.DateTimeFormat('en-US').
 *
 * Returns:
 *   {JSX.Element} The rendered History page.
 *
 * 中文说明:
 * 该组件用于展示最近的分析历史记录：挂载时从后端加载历史，支持按 SHA256 搜索并跳转到详情页，根据任务状态展示不同图标与样式，并处理加载/错误/空列表等状态。
 */
export default function History() {
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchHash, setSearchHash] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await axios.get(`${API_BASE}/history?limit=50`);
        setHistory(res.data);
      } catch (err) {
        console.error(err);
        setError("Failed to load history.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchHistory();
  }, []);

  const searchByHash = async () => {
    if (!searchHash) return;
    setIsSearching(true);
    setError(null);
    try {
      const res = await axios.get(`${API_BASE}/result/${searchHash}`);
      navigate(`/task/${res.data.task_id}`);
    } catch (err) {
      setError("Analysis not found for this hash.");
      setIsSearching(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-emerald-400" />;
      case 'failed':
        return <AlertCircle className="w-5 h-5 text-red-400" />;
      case 'pending':
      case 'processing':
        return <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />;
      default:
        return <Clock className="w-5 h-5 text-slate-400" />;
    }
  };

  const getStatusBadgeClass = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-emerald-900/30 text-emerald-400 border-emerald-800';
      case 'failed':
        return 'bg-red-900/30 text-red-400 border-red-800';
      case 'pending':
      case 'processing':
        return 'bg-cyan-900/30 text-cyan-400 border-cyan-800';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(date);
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
        <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
        <h3 className="text-2xl font-bold text-red-400">Error</h3>
        <p className="text-red-200 mt-2">{error}</p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      <header className="mb-8 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center">
            <Clock className="mr-3 text-cyan-400" /> Analysis History
          </h1>
          <p className="text-slate-400 mt-2">Recent malware analysis tasks</p>
        </div>
        
        {/* Search Input */}
        <div className="flex items-center space-x-2 bg-slate-800 p-2 rounded-xl border border-slate-700 shadow-lg w-full md:w-96">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input 
              type="text" 
              placeholder="Enter SHA256 Hash"
              className="w-full bg-slate-900 border border-slate-600 rounded-lg py-2 pl-10 pr-4 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 transition-colors"
              value={searchHash}
              onChange={(e) => setSearchHash(e.target.value)}
            />
          </div>
          <button 
            onClick={searchByHash}
            disabled={!searchHash || isSearching}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-bold rounded-lg transition-all disabled:opacity-50 cursor-pointer whitespace-nowrap"
          >
            {isSearching ? 'Searching...' : 'Search'}
          </button>
        </div>
      </header>

      <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-xl overflow-hidden">
        {history.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            No analysis history found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse table-fixed">
              <thead>
                <tr className="bg-slate-900/50 border-b border-slate-700 text-slate-300 text-sm uppercase tracking-wider">
                  <th className="p-4 font-medium w-32">Status</th>
                  <th className="p-4 font-medium w-1/3">Filename</th>
                  <th className="p-4 font-medium w-1/3">SHA256</th>
                  <th className="p-4 font-medium w-58">Date</th>
                  <th className="p-4 font-medium w-30">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {history.map((task) => (
                  <tr 
                    key={task.task_id} 
                    className="hover:bg-slate-700/30 transition-colors group"
                  >
                    <td className="p-4">
                      <div className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getStatusBadgeClass(task.status)}`}>
                        {getStatusIcon(task.status)}
                        <span className="ml-1.5 capitalize">{task.status}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center text-slate-200 font-medium truncate">
                        <FileText className="w-4 h-4 mr-2 text-slate-400 flex-shrink-0" />
                        <span className="truncate" title={task.filename || 'Unknown'}>
                          {task.filename || 'Unknown'}
                        </span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="text-slate-400 font-mono text-sm truncate" title={task.sha256}>
                        {task.sha256}
                      </div>
                    </td>
                    <td className="p-4 text-slate-400 text-sm">
                      {formatDate(task.created_at)}
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => navigate(`/task/${task.task_id}`)}
                        className="inline-flex items-center px-3 py-1.5 bg-slate-700 hover:bg-cyan-600 text-white text-sm font-medium rounded transition-colors cursor-pointer"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
