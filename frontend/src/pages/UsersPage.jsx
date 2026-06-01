import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { auth } from '../auth.js';
import { useFetch } from '../hooks/useFetch.js';

function _currentUsername() {
  try {
    const token = auth.getToken();
    if (!token) return null;
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.username || null;
  } catch {
    return null;
  }
}

export default function UsersPage() {
  if (!auth.isAdmin()) {
    navigate('/');
    return null;
  }

  const { data: users, loading, error, refetch } = useFetch('/users/');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newIsSuper, setNewIsSuper]   = useState(false);
  const [creating, setCreating]       = useState(false);
  const [resetId, setResetId]         = useState(null);
  const [resetPw, setResetPw]         = useState('');

  const currentUsername = _currentUsername();

  async function handleCreate(e) {
    e.preventDefault();
    setCreating(true);
    try {
      await apiPost('/users/create/', {
        username: newUsername.trim(),
        password: newPassword,
        is_superuser: newIsSuper,
      });
      toast.success(`User "${newUsername}" created.`);
      setNewUsername('');
      setNewPassword('');
      setNewIsSuper(false);
      refetch();
    } catch (err) {
      toast.error(err.message || 'Failed to create user.');
    } finally {
      setCreating(false);
    }
  }

  async function action(path, successMsg) {
    try {
      await apiPost(path, {});
      toast.success(successMsg);
      refetch();
    } catch (err) {
      toast.error(err.message || 'Action failed.');
    }
  }

  async function handleResetPassword(userId) {
    if (!resetPw || resetPw.length < 8) {
      toast.error('New password must be at least 8 characters.');
      return;
    }
    try {
      await apiPost(`/users/${userId}/reset-password/`, { password: resetPw });
      toast.success('Password reset.');
      setResetId(null);
      setResetPw('');
    } catch (err) {
      toast.error(err.message || 'Failed to reset password.');
    }
  }

  return (
    <Layout>
      <div className="p-6 max-w-4xl mx-auto space-y-6">
        <h1 className="text-lit font-bold text-xl">Users</h1>

        <Card>
          <CardHeader className="border-b border-border px-5 py-4">
            <CardTitle className="text-sm font-semibold">Create User</CardTitle>
          </CardHeader>
          <CardContent className="px-5 py-5">
            <form onSubmit={handleCreate} className="flex flex-wrap gap-3 items-end">
              <div className="flex flex-col gap-1">
                <label className="text-xs font-semibold text-dim uppercase tracking-wider">Username</label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={e => setNewUsername(e.target.value)}
                  required
                  className="field w-44"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-semibold text-dim uppercase tracking-wider">Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  required
                  minLength={8}
                  className="field w-44"
                />
              </div>
              <div className="flex items-center gap-2 pb-1">
                <input
                  id="is-super"
                  type="checkbox"
                  checked={newIsSuper}
                  onChange={e => setNewIsSuper(e.target.checked)}
                  className="accent-brand"
                />
                <label htmlFor="is-super" className="text-sm text-body">Superuser</label>
              </div>
              <Button type="submit" size="sm" disabled={creating}>
                {creating ? 'Creating…' : 'Create'}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="border-b border-border px-5 py-4">
            <CardTitle className="text-sm font-semibold">All Users</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loading && <div className="p-6 flex justify-center"><Spinner /></div>}
            {error && <p className="p-5 text-sm text-red-400">Failed to load users.</p>}
            {users && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Superuser</TableHead>
                    <TableHead>Active</TableHead>
                    <TableHead>Joined</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map(u => {
                    const isSelf = u.username === currentUsername;
                    return (
                      <TableRow key={u.id}>
                        <TableCell className="font-medium">
                          {u.username}
                          {isSelf && <span className="ml-2 text-xs text-dim">(you)</span>}
                        </TableCell>
                        <TableCell>{u.is_superuser ? '✓' : '—'}</TableCell>
                        <TableCell>
                          <span className={u.is_active ? 'text-green-400' : 'text-red-400'}>
                            {u.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </TableCell>
                        <TableCell className="text-dim text-xs">
                          {new Date(u.date_joined).toLocaleDateString()}
                        </TableCell>
                        <TableCell>
                          {!isSelf && (
                            <div className="flex flex-wrap gap-2 items-center">
                              {resetId === u.id ? (
                                <div className="flex gap-2 items-center">
                                  <input
                                    type="password"
                                    value={resetPw}
                                    onChange={e => setResetPw(e.target.value)}
                                    placeholder="New password"
                                    className="field w-36 text-xs"
                                  />
                                  <Button size="sm" onClick={() => handleResetPassword(u.id)}>Set</Button>
                                  <Button size="sm" variant="outline" onClick={() => { setResetId(null); setResetPw(''); }}>Cancel</Button>
                                </div>
                              ) : (
                                <Button size="sm" variant="outline" onClick={() => setResetId(u.id)}>
                                  Reset Password
                                </Button>
                              )}
                              {u.is_active
                                ? <Button size="sm" variant="outline" onClick={() => action(`/users/${u.id}/deactivate/`, 'User deactivated.')}>Deactivate</Button>
                                : <Button size="sm" variant="outline" onClick={() => action(`/users/${u.id}/reactivate/`, 'User reactivated.')}>Reactivate</Button>
                              }
                              {u.is_superuser
                                ? <Button size="sm" variant="outline" onClick={() => action(`/users/${u.id}/demote/`, 'Superuser removed.')}>Demote</Button>
                                : <Button size="sm" variant="outline" onClick={() => action(`/users/${u.id}/promote/`, 'Promoted to superuser.')}>Promote</Button>
                              }
                              <ConfirmButton
                                label="Delete"
                                confirmLabel={`Delete user "${u.username}"?`}
                                onConfirm={() => action(`/users/${u.id}/delete/`, `User "${u.username}" deleted.`)}
                              />
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
}
