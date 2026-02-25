import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';
import { AlertCircle, Loader2, ArrowLeft } from 'lucide-react';
import ReportView from '../components/ReportView';

const API_BASE = "/api";
const STATUS = {
  idle: "idle",
  pending: "pending",
  processing: "processing",
  completed: "completed",
  failed: "failed",
};
const POLL_INTERVAL_MS = 2000;

function isInProgress(status) {
  return status === STATUS.pending || status === STATUS.processing;
}

export default function TaskDetail() {
  const { taskId } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState(STATUS.idle);
  const [report, setReport] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  const applyTaskState = (taskData) => {
    if (!taskData) return;
    setStatus(taskData.status);

    if (taskData.status === STATUS.completed) {
      setReport(taskData);
      return;
    }
    if (taskData.status === STATUS.failed) {
      setErrorMessage(taskData.error || "Analysis failed.");
    }
  };

  const fetchStatus = async (id) => {
    try {
      const res = await axios.get(`${API_BASE}/tasks/${id}`);
      applyTaskState(res.data);
    } catch (err) {
      console.error(err);
      if (err.response?.status === 404) {
        setErrorMessage("Task not found.");
        setStatus(STATUS.failed);
      }
    }
  };

  useEffect(() => {
    if (!taskId) return;
    
    // Initial fetch
    fetchStatus(taskId);

    let interval;
    interval = setInterval(() => {
      setStatus((currentStatus) => {
        if (isInProgress(currentStatus) || currentStatus === STATUS.idle) {
          fetchStatus(taskId);
        } else {
          clearInterval(interval);
        }
        return currentStatus;
      });
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [taskId]);

  return (
    <div className="max-w-7xl mx-auto">
      <button 
        onClick={() => navigate(-1)}
        className="mb-6 flex items-center text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4 mr-2" /> Back
      </button>

      {status !== STATUS.idle && (
        <div className="animate-in fade-in duration-500">
           {isInProgress(status) ? (
             <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
               <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
               <h3 className="text-2xl font-bold text-white">Analysis in Progress...</h3>
               <p className="text-slate-400 mt-2">
                 AI Agents are auditing the binary. This may take a few minutes.
                 <br/>
                 Current State: <span className="text-cyan-400 uppercase">{status}</span>
               </p>
             </div>
           ) : null}

           {status === STATUS.failed && (
             <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
               <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
               <h3 className="text-2xl font-bold text-red-400">Analysis Failed</h3>
               <p className="text-red-200 mt-2">{errorMessage}</p>
             </div>
           )}

           {status === STATUS.completed && report && (
             <ReportView report={report} />
           )}
        </div>
      )}
    </div>
  );
}
