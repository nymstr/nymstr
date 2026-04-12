import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import type { Conversation, Message } from "@/types";
import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { Button } from "@/components/shadcn/button";
import { Input } from "@/components/shadcn/input";
import {
  Send,
  ArrowLeft,
  MoreHorizontal,
  Check,
  CheckCheck,
  Clock,
  Users,
  AlertCircle,
} from "lucide-react";
import { format } from "date-fns";
import { useMessages } from "@/hooks/useMessages";
import { useMessageSend } from "@/hooks/useMessageSend";
import { useChatStore } from "@/stores/chatStore";

interface ChatViewProps {
  conversation: Conversation;
  onBack?: () => void;
}

function initials(name: string) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((n) => n[0]!.toUpperCase())
    .join("");
}

function statusIcon(status: Message["status"]) {
  switch (status) {
    case "pending":
    case "encrypting":
      return <Clock className="h-3 w-3 text-muted-foreground" />;
    case "sent":
      return <Check className="h-3 w-3 text-muted-foreground" />;
    case "delivered":
      return <CheckCheck className="h-3 w-3 text-accent" />;
    case "failed":
      return <AlertCircle className="h-3 w-3 text-destructive" />;
    default:
      return null;
  }
}

export function ChatView({ conversation, onBack }: ChatViewProps) {
  const [draft, setDraft] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const { messages } = useMessages(
    conversation.type === "direct" ? conversation.id : null,
  );
  const groupMessages = useChatStore((s) =>
    conversation.type === "group" ? s.messages.get(conversation.id) : undefined,
  );
  const allMessages = conversation.type === "group"
    ? (groupMessages ?? [])
    : messages;

  const { sendMessage } = useMessageSend(conversation.id, conversation.type);

  const pendingHandshake = useChatStore((s) =>
    s.pendingHandshakes.has(conversation.id),
  );

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [allMessages.length]);

  const handleSend = async () => {
    const content = draft.trim();
    if (!content) return;
    setDraft("");
    try {
      await sendMessage(content);
    } catch (err) {
      console.error("[ChatView] send failed:", err);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const isGroup = conversation.type === "group";

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        {onBack && (
          <Button
            variant="ghost"
            size="icon"
            onClick={onBack}
            className="mr-1 md:hidden"
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
        )}
        <Avatar className="h-10 w-10">
          <AvatarFallback>
            {isGroup ? <Users className="h-5 w-5" /> : initials(conversation.name)}
          </AvatarFallback>
        </Avatar>
        <div className="flex-1">
          <h2 className="font-semibold text-foreground">{conversation.name}</h2>
          <p className="text-xs text-muted-foreground">
            {isGroup
              ? `${conversation.memberCount ?? 0} members`
              : conversation.online
                ? "Online"
                : "Offline"}
          </p>
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="text-muted-foreground hover:text-foreground"
        >
          <MoreHorizontal className="h-5 w-5" />
        </Button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="mx-auto max-w-2xl space-y-4">
          {allMessages.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <p className="text-sm text-muted-foreground">
                {pendingHandshake
                  ? "Waiting for secure session..."
                  : "No messages yet. Say hello!"}
              </p>
            </div>
          ) : (
            allMessages.map((msg) => (
              <div
                key={msg.id}
                className={cn(
                  "flex items-end gap-2",
                  msg.isOwn && "flex-row-reverse",
                )}
              >
                {!msg.isOwn && (
                  <Avatar className="h-8 w-8">
                    <AvatarFallback>
                      {initials(msg.senderDisplayName || msg.sender)}
                    </AvatarFallback>
                  </Avatar>
                )}
                <div
                  className={cn(
                    "group flex max-w-[75%] flex-col gap-1",
                    msg.isOwn && "items-end",
                  )}
                >
                  {isGroup && !msg.isOwn && (
                    <span className="px-1 text-xs font-medium text-muted-foreground">
                      {msg.senderDisplayName || msg.sender}
                    </span>
                  )}
                  <div
                    className={cn(
                      "rounded-2xl px-4 py-2",
                      msg.isOwn
                        ? "rounded-br-md bg-primary text-primary-foreground"
                        : "rounded-bl-md bg-secondary text-secondary-foreground",
                    )}
                  >
                    <p className="text-sm leading-relaxed whitespace-pre-wrap break-words">
                      {msg.content}
                    </p>
                  </div>
                  <div className="flex items-center gap-1 px-1">
                    <span className="text-xs text-muted-foreground">
                      {format(new Date(msg.timestamp), "h:mm a")}
                    </span>
                    {msg.isOwn && statusIcon(msg.status)}
                  </div>
                </div>
              </div>
            ))
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Composer */}
      <div className="border-t border-border p-4">
        <div className="mx-auto flex max-w-2xl items-center gap-2">
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={pendingHandshake ? "Setting up secure session..." : "Type a message..."}
            disabled={pendingHandshake}
            className="flex-1 rounded-full bg-secondary border-0 px-4 py-5 focus-visible:ring-1 focus-visible:ring-accent"
          />
          <Button
            onClick={handleSend}
            disabled={!draft.trim() || pendingHandshake}
            size="icon"
            className="h-10 w-10 shrink-0 rounded-full"
          >
            <Send className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
