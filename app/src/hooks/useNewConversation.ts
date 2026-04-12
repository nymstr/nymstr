import { useCallback, useState } from 'react';
import * as api from '../services/api';
import { useChatStore } from '../stores/chatStore';

export type ConversationStatus =
  | 'idle'
  | 'querying'
  | 'not_found'
  | 'found'
  | 'ready'
  | 'initiating'
  | 'pending_handshake'
  | 'error';

export interface FoundUser {
  username: string;
  publicKey: string;
}

export function useNewConversation() {
  const [status, setStatus] = useState<ConversationStatus>('idle');
  const [error, setError] = useState<string | null>(null);
  const [foundUser, setFoundUser] = useState<FoundUser | null>(null);

  const addPendingHandshake = useChatStore((s) => s.addPendingHandshake);
  const removePendingHandshake = useChatStore((s) => s.removePendingHandshake);
  const addConversation = useChatStore((s) => s.addConversation);
  const conversations = useChatStore((s) => s.conversations);

  /**
   * Step 1: look up a user by username. Sets status to `ready` if we already
   * have a conversation with them, `found` if new, or `not_found`.
   */
  const lookupUser = useCallback(
    async (username: string): Promise<FoundUser | null> => {
      setError(null);
      setFoundUser(null);
      setStatus('querying');

      try {
        const user = await api.queryUser(username);
        if (!user) {
          setStatus('not_found');
          return null;
        }

        setFoundUser(user);

        const existsLocal = conversations.some((c) => c.id === user.username);
        if (existsLocal) {
          setStatus('ready');
          return user;
        }

        const existsBackend = await api.checkConversationExists(user.username);
        if (existsBackend) {
          addConversation({
            id: user.username,
            type: 'direct',
            name: user.username,
            unreadCount: 0,
            online: false,
          });
          setStatus('ready');
          return user;
        }

        setStatus('found');
        return user;
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Lookup failed');
        setStatus('error');
        return null;
      }
    },
    [addConversation, conversations],
  );

  /**
   * Step 2: initiate the MLS handshake. Adds the conversation to the sidebar
   * immediately with a pending-handshake marker so the user can see it.
   */
  const startChat = useCallback(
    async (username: string): Promise<string | null> => {
      setError(null);
      setStatus('initiating');
      addPendingHandshake(username);
      addConversation({
        id: username,
        type: 'direct',
        name: username,
        unreadCount: 0,
        online: false,
      });

      try {
        await api.initiateConversation(username);
        await api.addContact(username);
        setStatus('pending_handshake');
        return username;
      } catch (err) {
        removePendingHandshake(username);
        setError(err instanceof Error ? err.message : 'Failed to start chat');
        setStatus('error');
        return null;
      }
    },
    [addPendingHandshake, removePendingHandshake, addConversation],
  );

  const reset = useCallback(() => {
    setStatus('idle');
    setError(null);
    setFoundUser(null);
  }, []);

  return { status, error, foundUser, lookupUser, startChat, reset };
}
