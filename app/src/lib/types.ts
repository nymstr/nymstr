export interface User {
  id: string;
  name: string;
  username: string;
  avatar: string;
  status: "online" | "offline" | "away";
}

export interface Message {
  id: string;
  senderId: string;
  content: string;
  timestamp: Date;
  status: "sent" | "delivered" | "read";
}

export type RequestStatus = "accepted" | "pending_sent" | "pending_received";

export interface Conversation {
  id: string;
  participant: User;
  messages: Message[];
  lastMessage?: Message;
  unreadCount: number;
  requestStatus: RequestStatus;
}
