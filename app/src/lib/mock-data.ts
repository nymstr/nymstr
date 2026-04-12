import type { Conversation, User } from "./types"

export const currentUser: User = {
  id: "user-1",
  name: "You",
  username: "me",
  avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=you",
  status: "online",
}

// Mock users for search functionality
export const mockSearchableUsers: User[] = [
  {
    id: "user-6",
    name: "Emma Watson",
    username: "emmawatson",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=emma",
    status: "online",
  },
  {
    id: "user-7",
    name: "James Miller",
    username: "jmiller",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=james",
    status: "offline",
  },
  {
    id: "user-8",
    name: "Olivia Johnson",
    username: "oliviaj",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=olivia",
    status: "away",
  },
  {
    id: "user-9",
    name: "Liam Brown",
    username: "liambrown",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=liam",
    status: "online",
  },
  {
    id: "user-10",
    name: "Sophia Davis",
    username: "sophiad",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=sophia",
    status: "offline",
  },
  {
    id: "user-11",
    name: "Noah Wilson",
    username: "noahw",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=noah",
    status: "online",
  },
  {
    id: "user-12",
    name: "Ava Martinez",
    username: "avamartinez",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=ava",
    status: "away",
  },
  {
    id: "user-13",
    name: "William Anderson",
    username: "wanderson",
    avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=william",
    status: "online",
  },
]

export const mockConversations: Conversation[] = [
  {
    id: "conv-1",
    participant: {
      id: "user-2",
      name: "Sarah Chen",
      username: "sarahchen",
      avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=sarah",
      status: "online",
    },
    messages: [
      {
        id: "msg-1",
        senderId: "user-2",
        content: "Hey! Are you coming to the meeting today?",
        timestamp: new Date(Date.now() - 3600000),
        status: "read",
      },
      {
        id: "msg-2",
        senderId: "user-1",
        content: "Yes, I'll be there in 10 minutes",
        timestamp: new Date(Date.now() - 3500000),
        status: "read",
      },
      {
        id: "msg-3",
        senderId: "user-2",
        content: "Great work on the slides! Love it! Just one more thing...",
        timestamp: new Date(Date.now() - 3400000),
        status: "read",
      },
    ],
    unreadCount: 0,
    requestStatus: "accepted",
    get lastMessage() {
      return this.messages[this.messages.length - 1]
    },
  },
  {
    id: "conv-2",
    participant: {
      id: "user-3",
      name: "Alex Rivera",
      username: "alexr",
      avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=alex",
      status: "away",
    },
    messages: [
      {
        id: "msg-4",
        senderId: "user-3",
        content: "Can you review the PR when you get a chance?",
        timestamp: new Date(Date.now() - 7200000),
        status: "read",
      },
      {
        id: "msg-5",
        senderId: "user-1",
        content: "Sure, I'll take a look this afternoon",
        timestamp: new Date(Date.now() - 7100000),
        status: "delivered",
      },
    ],
    unreadCount: 0,
    requestStatus: "accepted",
    get lastMessage() {
      return this.messages[this.messages.length - 1]
    },
  },
  {
    id: "conv-3",
    participant: {
      id: "user-4",
      name: "Jordan Park",
      username: "jordanp",
      avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=jordan",
      status: "offline",
    },
    messages: [
      {
        id: "msg-6",
        senderId: "user-4",
        content: "Thanks for your help yesterday!",
        timestamp: new Date(Date.now() - 86400000),
        status: "read",
      },
    ],
    unreadCount: 1,
    requestStatus: "accepted",
    get lastMessage() {
      return this.messages[this.messages.length - 1]
    },
  },
  {
    id: "conv-4",
    participant: {
      id: "user-5",
      name: "Morgan Taylor",
      username: "morgant",
      avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=morgan",
      status: "online",
    },
    messages: [
      {
        id: "msg-7",
        senderId: "user-5",
        content: "Did you see the new design mockups?",
        timestamp: new Date(Date.now() - 172800000),
        status: "read",
      },
      {
        id: "msg-8",
        senderId: "user-1",
        content: "Yes! They look amazing",
        timestamp: new Date(Date.now() - 172700000),
        status: "read",
      },
    ],
    unreadCount: 0,
    requestStatus: "accepted",
    get lastMessage() {
      return this.messages[this.messages.length - 1]
    },
  },
]

// Mock incoming message requests from other users
export const mockIncomingRequests: Conversation[] = [
  {
    id: "req-1",
    participant: {
      id: "user-14",
      name: "Elena Rodriguez",
      username: "elenarodriguez",
      avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=elena",
      status: "online",
    },
    messages: [
      {
        id: "req-msg-1",
        senderId: "user-14",
        content: "Hi! I saw your work on the design project. Would love to connect!",
        timestamp: new Date(Date.now() - 1800000),
        status: "delivered",
      },
    ],
    unreadCount: 1,
    requestStatus: "pending_received",
    get lastMessage() {
      return this.messages[this.messages.length - 1]
    },
  },
  {
    id: "req-2",
    participant: {
      id: "user-15",
      name: "Marcus Chen",
      username: "marcusc",
      avatar: "https://api.dicebear.com/9.x/notionists/svg?seed=marcus",
      status: "offline",
    },
    messages: [
      {
        id: "req-msg-2",
        senderId: "user-15",
        content: "Hey, we met at the conference last week. Remember me?",
        timestamp: new Date(Date.now() - 7200000),
        status: "delivered",
      },
    ],
    unreadCount: 1,
    requestStatus: "pending_received",
    get lastMessage() {
      return this.messages[this.messages.length - 1]
    },
  },
]
