import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api } from './api';

const WorkspaceContext = createContext(null);

export function WorkspaceProvider({ children }) {
  const [repos, setRepos] = useState([]);
  const [repoId, setRepoId] = useState('');
  const [error, setError] = useState(null);

  const refreshRepos = useCallback(async () => {
    try {
      const data = await api('/repositories');
      setRepos(Array.isArray(data) ? data : []);
      setError(null);
      return data;
    } catch (err) {
      setError(err.message);
      return [];
    }
  }, []);

  useEffect(() => {
    refreshRepos();
  }, [refreshRepos]);

  useEffect(() => {
    if (repoId && !repos.some((repo) => String(repo.id) === String(repoId))) {
      setRepoId('');
    }
  }, [repos, repoId]);

  const value = useMemo(
    () => ({
      repos,
      repoId,
      setRepoId,
      refreshRepos,
      error,
      selectedRepo: repos.find((repo) => String(repo.id) === String(repoId)) || null,
    }),
    [repos, repoId, refreshRepos, error]
  );

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace() {
  const context = useContext(WorkspaceContext);
  if (!context) throw new Error('useWorkspace must be used inside WorkspaceProvider');
  return context;
}
