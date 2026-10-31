/** 主界面：桌面双栏（会话列表 + 聊天窗），窄屏单列切换（CSS media query）。 */
import { useState } from "react";

import { openChat, useAppState } from "../lib/app";

import AddFriendModal from "../components/AddFriendModal";
import ChatPanel from "../components/ChatPanel";
import ContactSidebar from "../components/ContactSidebar";
import ProfileModal from "../components/ProfileModal";

export default function MainPage() {
  const state = useAppState();
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  return (
    <div className={`main-layout${state.activeDid !== null ? " chat-open" : ""}`}>
      <ContactSidebar onAddFriend={() => setShowAddFriend(true)} onOpenProfile={() => setShowProfile(true)} />
      <ChatPanel onBack={() => openChat(null)} onAddFriend={() => setShowAddFriend(true)} />
      {showAddFriend && <AddFriendModal onClose={() => setShowAddFriend(false)} />}
      {showProfile && <ProfileModal onClose={() => setShowProfile(false)} />}
    </div>
  );
}
