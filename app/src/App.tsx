import { useEffect } from 'react';
import { AuthView } from './components/ported/auth-view';
import { MessengerPage } from './components/ported/messenger-page';
import { ToastContainer } from './components/ui/Toast';
import { ErrorBoundary } from './components/ErrorBoundary';
import { useAuthStore } from './stores/authStore';
import { useChatStore } from './stores/chatStore';
import { useAppEvents } from './hooks/useAppEvents';
import * as api from './services/api';
import { Loader2 } from 'lucide-react';

function App() {
  const status = useAuthStore((s) => s.status);
  const progress = useAuthStore((s) => s.progress);
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated);
  const setUnauthenticated = useAuthStore((s) => s.setUnauthenticated);
  const setConversations = useChatStore((s) => s.setConversations);
  const setContacts = useChatStore((s) => s.setContacts);

  useAppEvents();

  useEffect(() => {
    const checkAuth = async () => {
      try {
        await api.initialize();
        setUnauthenticated();
      } catch (error) {
        console.error('Failed to initialize:', error);
        setUnauthenticated();
      }
    };
    checkAuth();
  }, [setAuthenticated, setUnauthenticated]);

  useEffect(() => {
    if (status !== 'authenticated') return;
    const loadData = async () => {
      try {
        const contacts = await api.getContacts();
        setContacts(contacts);
        const convs = contacts.map((contact) => ({
          id: contact.username,
          type: 'direct' as const,
          name: contact.displayName || contact.username,
          avatarUrl: contact.avatarUrl,
          lastMessage: undefined,
          lastMessageTime: contact.lastSeen,
          unreadCount: contact.unreadCount,
          online: contact.online,
        }));
        setConversations(convs);

        try {
          const groups = await api.getJoinedGroups();
          const seenAddresses = new Set<string>();
          const uniqueGroups = groups.filter((group) => {
            if (seenAddresses.has(group.address)) return false;
            seenAddresses.add(group.address);
            return true;
          });
          const groupConvs = uniqueGroups.map((group) => ({
            id: group.address,
            type: 'group' as const,
            name: group.name,
            lastMessage: undefined,
            lastMessageTime: undefined,
            unreadCount: 0,
            memberCount: group.memberCount,
            groupAddress: group.address,
          }));
          const existingIds = new Set(convs.map((c) => c.id));
          const newGroupConvs = groupConvs.filter((g) => !existingIds.has(g.id));
          setConversations([...convs, ...newGroupConvs]);
        } catch (e) {
          console.log('Groups not available:', e);
        }
      } catch (error) {
        console.error('Failed to load data:', error);
      }
    };
    loadData();
  }, [status, setContacts, setConversations]);

  if (status === 'loading') {
    return (
      <>
        <div className="h-screen flex items-center justify-center bg-background">
          <div className="text-center">
            <Loader2 className="w-12 h-12 animate-spin text-accent mx-auto mb-4" />
            <p className="text-muted-foreground">Loading...</p>
          </div>
        </div>
        <ToastContainer />
      </>
    );
  }

  if (status === 'authenticating') {
    return (
      <>
        <div className="h-screen flex items-center justify-center bg-background">
          <div className="text-center">
            <Loader2 className="w-12 h-12 animate-spin text-accent mx-auto mb-4" />
            <p className="text-muted-foreground">
              {progress?.message || 'Authenticating...'}
            </p>
          </div>
        </div>
        <ToastContainer />
      </>
    );
  }

  if (status === 'unauthenticated') {
    return (
      <>
        <AuthView />
        <ToastContainer />
      </>
    );
  }

  return (
    <ErrorBoundary>
      <MessengerPage />
      <ToastContainer />
    </ErrorBoundary>
  );
}

export default App;
