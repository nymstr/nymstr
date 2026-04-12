import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { Button } from "@/components/shadcn/button";
import { ArrowLeft, UserCheck, UserX, Inbox, Users, Loader2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useEffect } from "react";
import { useGroupStore } from "@/stores/groupStore";
import { useChatStore } from "@/stores/chatStore";
import * as api from "@/services/api";
import { showToast } from "@/hooks/useToast";

interface MessageRequestsProps {
  onClose: () => void;
  onOpenConversation: (conversationId: string) => void;
}

function initials(name: string) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((n) => n[0]!.toUpperCase())
    .join("");
}

export function MessageRequests({
  onClose,
  onOpenConversation,
}: MessageRequestsProps) {
  const contactRequests = useGroupStore((s) => s.contactRequests);
  const pendingWelcomes = useGroupStore((s) => s.pendingWelcomes);
  const setContactRequests = useGroupStore((s) => s.setContactRequests);
  const setPendingWelcomes = useGroupStore((s) => s.setPendingWelcomes);
  const removeContactRequest = useGroupStore((s) => s.removeContactRequest);
  const removePendingWelcome = useGroupStore((s) => s.removePendingWelcome);
  const processingWelcomes = useGroupStore((s) => s.processingWelcomes);
  const setProcessingWelcome = useGroupStore((s) => s.setProcessingWelcome);
  const addConversation = useChatStore((s) => s.addConversation);

  useEffect(() => {
    api.getContactRequests().then(setContactRequests).catch((e) =>
      console.error("[Inbox] getContactRequests failed:", e),
    );
    api.getPendingWelcomes().then(setPendingWelcomes).catch((e) =>
      console.error("[Inbox] getPendingWelcomes failed:", e),
    );
  }, [setContactRequests, setPendingWelcomes]);

  const totalCount = contactRequests.length + pendingWelcomes.length;

  const handleAcceptContact = async (fromUsername: string) => {
    try {
      const { conversationId } = await api.acceptContactRequest(fromUsername);
      addConversation({
        id: conversationId || fromUsername,
        type: "direct",
        name: fromUsername,
        unreadCount: 0,
        online: false,
      });
      removeContactRequest(
        contactRequests.find((r) => r.fromUsername === fromUsername)?.id ?? -1,
      );
      showToast.success("Request accepted", `@${fromUsername}`);
      onOpenConversation(conversationId || fromUsername);
    } catch (err) {
      showToast.error(
        "Accept failed",
        err instanceof Error ? err.message : "Unknown error",
      );
    }
  };

  const handleDenyContact = async (fromUsername: string, requestId: number) => {
    try {
      await api.denyContactRequest(fromUsername);
      removeContactRequest(requestId);
    } catch (err) {
      showToast.error(
        "Deny failed",
        err instanceof Error ? err.message : "Unknown error",
      );
    }
  };

  const handleAcceptWelcome = async (welcomeId: number) => {
    setProcessingWelcome(welcomeId, true);
    try {
      await api.processWelcome(welcomeId);
      removePendingWelcome(welcomeId);
      showToast.success("Joined group", "Welcome processed");
    } catch (err) {
      showToast.error(
        "Failed to join group",
        err instanceof Error ? err.message : "Unknown error",
      );
    } finally {
      setProcessingWelcome(welcomeId, false);
    }
  };

  const handleDenyWelcome = async (welcomeId: number) => {
    setProcessingWelcome(welcomeId, true);
    try {
      await api.denyWelcome(welcomeId);
      removePendingWelcome(welcomeId);
    } catch (err) {
      showToast.error(
        "Deny failed",
        err instanceof Error ? err.message : "Unknown error",
      );
    } finally {
      setProcessingWelcome(welcomeId, false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <h2 className="font-semibold text-foreground">Inbox</h2>
          <p className="text-xs text-muted-foreground">
            {totalCount} pending{totalCount !== 1 ? " items" : " item"}
          </p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {totalCount === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-secondary">
              <Inbox className="h-8 w-8 text-muted-foreground" />
            </div>
            <div>
              <h3 className="font-medium text-foreground">Nothing pending</h3>
              <p className="mt-1 text-sm text-muted-foreground">
                Message requests and group invites will appear here.
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col divide-y divide-border">
            {contactRequests.map((req) => (
              <div
                key={`c-${req.id}`}
                className="flex flex-col gap-3 p-4 transition-colors hover:bg-secondary/30"
              >
                <div className="flex items-start gap-3">
                  <Avatar className="h-12 w-12">
                    <AvatarFallback>{initials(req.fromUsername)}</AvatarFallback>
                  </Avatar>
                  <div className="flex-1 overflow-hidden">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-foreground">
                        @{req.fromUsername}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {formatDistanceToNow(new Date(req.receivedAt), {
                          addSuffix: false,
                        })}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Wants to message you
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    onClick={() => handleAcceptContact(req.fromUsername)}
                    size="sm"
                    className="flex-1 gap-2"
                  >
                    <UserCheck className="h-4 w-4" />
                    Accept
                  </Button>
                  <Button
                    onClick={() => handleDenyContact(req.fromUsername, req.id)}
                    variant="outline"
                    size="sm"
                    className="flex-1 gap-2"
                  >
                    <UserX className="h-4 w-4" />
                    Decline
                  </Button>
                </div>
              </div>
            ))}

            {pendingWelcomes.map((w) => {
              const busy = processingWelcomes.has(w.id);
              return (
                <div
                  key={`w-${w.id}`}
                  className="flex flex-col gap-3 p-4 transition-colors hover:bg-secondary/30"
                >
                  <div className="flex items-start gap-3">
                    <Avatar className="h-12 w-12">
                      <AvatarFallback>
                        <Users className="h-5 w-5" />
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1 overflow-hidden">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-foreground">
                          {w.groupName || `Group ${w.groupId.substring(0, 8)}`}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {formatDistanceToNow(new Date(w.receivedAt), {
                            addSuffix: false,
                          })}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Invite from @{w.sender}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      onClick={() => handleAcceptWelcome(w.id)}
                      size="sm"
                      className="flex-1 gap-2"
                      disabled={busy}
                    >
                      {busy ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <UserCheck className="h-4 w-4" />
                      )}
                      Join
                    </Button>
                    <Button
                      onClick={() => handleDenyWelcome(w.id)}
                      variant="outline"
                      size="sm"
                      className="flex-1 gap-2"
                      disabled={busy}
                    >
                      <UserX className="h-4 w-4" />
                      Decline
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
