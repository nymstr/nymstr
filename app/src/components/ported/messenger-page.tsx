import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { ConversationList } from "./conversation-list";
import { ChatView } from "./chat-view";
import { EmptyChat } from "./empty-chat";
import { UserSearch } from "./user-search";
import { MessageRequests } from "./message-requests";
import { SettingsPanel } from "./settings-panel";
import { GroupJoinModal } from "./group-join-modal";
import { Button } from "@/components/shadcn/button";
import { Input } from "@/components/shadcn/input";
import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { Search, Edit, Settings, Inbox, Users } from "lucide-react";
import { useChatStore } from "@/stores/chatStore";
import { useAuthStore } from "@/stores/authStore";
import { useGroupStore } from "@/stores/groupStore";

type Panel = "chat" | "userSearch" | "requests" | "settings";

function initials(name: string) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((n) => n[0]!.toUpperCase())
    .join("");
}

export function MessengerPage() {
  const user = useAuthStore((s) => s.user);
  const conversations = useChatStore((s) => s.conversations);
  const activeConversationId = useChatStore((s) => s.activeConversationId);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);
  const contactRequestsCount = useGroupStore(
    (s) => s.contactRequests.length + s.pendingWelcomes.length,
  );

  const [searchQuery, setSearchQuery] = useState("");
  const [sidebarWidth, setSidebarWidth] = useState(384);
  const [isResizing, setIsResizing] = useState(false);
  const [activePanel, setActivePanel] = useState<Panel>("chat");
  const [showGroupJoin, setShowGroupJoin] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const minWidth = 280;
  const maxWidth = 600;

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!isResizing || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const w = e.clientX - rect.left;
      if (w >= minWidth && w <= maxWidth) setSidebarWidth(w);
    };
    const onUp = () => setIsResizing(false);
    if (isResizing) {
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }
    return () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [isResizing]);

  const selectedConversation = activeConversationId
    ? conversations.find((c) => c.id === activeConversationId)
    : null;

  const filteredConversations = conversations.filter((c) =>
    c.name.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const handleSelectConversation = (id: string) => {
    setActiveConversation(id);
    setActivePanel("chat");
  };

  const togglePanel = (p: Panel) =>
    setActivePanel((cur) => (cur === p ? "chat" : p));

  return (
    <div ref={containerRef} className="flex h-dvh bg-background">
      <div
        style={{ width: sidebarWidth }}
        className={cn(
          "relative flex flex-shrink-0 flex-col border-r border-border bg-card max-md:!w-full",
          activeConversationId && "hidden md:flex",
        )}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-3">
            <Avatar className="h-9 w-9">
              <AvatarFallback>
                {user ? initials(user.displayName || user.username) : "?"}
              </AvatarFallback>
            </Avatar>
            <h1 className="text-lg font-semibold text-foreground">Messages</h1>
          </div>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              className={cn(
                "text-muted-foreground hover:text-foreground",
                activePanel === "userSearch" && "bg-secondary text-foreground",
              )}
              onClick={() => togglePanel("userSearch")}
              title="New message"
            >
              <Edit className="h-5 w-5" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setShowGroupJoin(true)}
              className="text-muted-foreground hover:text-foreground"
              title="Join group"
            >
              <Users className="h-5 w-5" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className={cn(
                "relative text-muted-foreground hover:text-foreground",
                activePanel === "requests" && "bg-secondary text-foreground",
              )}
              onClick={() => togglePanel("requests")}
              title="Inbox"
            >
              <Inbox className="h-5 w-5" />
              {contactRequestsCount > 0 && (
                <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-accent px-1 text-[10px] font-medium text-accent-foreground">
                  {contactRequestsCount}
                </span>
              )}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className={cn(
                "text-muted-foreground hover:text-foreground",
                activePanel === "settings" && "bg-secondary text-foreground",
              )}
              onClick={() => togglePanel("settings")}
              title="Settings"
            >
              <Settings className="h-5 w-5" />
            </Button>
          </div>
        </div>

        <div className="p-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search conversations..."
              className="pl-9 bg-secondary border-0 rounded-full focus-visible:ring-1 focus-visible:ring-accent"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          <ConversationList
            conversations={filteredConversations}
            selectedId={activeConversationId}
            onSelect={handleSelectConversation}
          />
        </div>

        <div
          onMouseDown={() => setIsResizing(true)}
          className={cn(
            "absolute right-0 top-0 hidden h-full w-1 cursor-col-resize md:block hover:bg-accent/50 transition-colors",
            isResizing && "bg-accent",
          )}
        />
      </div>

      <div
        className={cn(
          "flex flex-1 flex-col bg-background",
          !activeConversationId && "hidden md:flex",
        )}
      >
        {activePanel === "settings" ? (
          <SettingsPanel onClose={() => setActivePanel("chat")} />
        ) : activePanel === "userSearch" ? (
          <UserSearch
            onOpenConversation={(id) => {
              setActiveConversation(id);
              setActivePanel("chat");
            }}
            onClose={() => setActivePanel("chat")}
          />
        ) : activePanel === "requests" ? (
          <MessageRequests
            onClose={() => setActivePanel("chat")}
            onOpenConversation={(id) => {
              setActiveConversation(id);
              setActivePanel("chat");
            }}
          />
        ) : selectedConversation ? (
          <ChatView
            conversation={selectedConversation}
            onBack={() => setActiveConversation(null)}
          />
        ) : (
          <EmptyChat />
        )}
      </div>

      {showGroupJoin && (
        <GroupJoinModal
          onClose={() => setShowGroupJoin(false)}
          onJoined={(addr) => {
            setActiveConversation(addr);
            setActivePanel("chat");
          }}
        />
      )}
    </div>
  );
}
