/** 主界面：守护者恢复横幅 + 桌面双栏（会话列表 + 聊天窗），窄屏单列切换（CSS media query）。 */
import { useState } from "react";

import { openChat, openChatView, openTimeline, useAppState } from "../lib/app";

import AddFriendModal from "../components/AddFriendModal";
import ChatPanel from "../components/ChatPanel";
import ContactSidebar from "../components/ContactSidebar";
import CreateGroupModal from "../components/CreateGroupModal";
import ProfileModal from "../components/ProfileModal";
import RecoveryRequestBanner from "../components/RecoveryRequestBanner";
import TimelinePage from "../components/TimelinePage";

export default function MainPage() {
  const state = useAppState();
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);

  return (
    <div className="main-root">
      <RecoveryRequestBanner />
      <div className={`main-layout${state.view === "chat" && state.activeDid !== null ? " chat-open" : ""}`}>
        <ContactSidebar
          onAddFriend={() => setShowAddFriend(true)}
          onOpenProfile={() => setShowProfile(true)}
          onCreateGroup={() => setShowCreateGroup(true)}
          onOpenTimeline={() => openTimeline()}
        />
        {state.view === "timeline" ? (
          <TimelinePage onBack={() => openChatView()} />
        ) : (
          <ChatPanel onBack={() => openChat(null)} onAddFriend={() => setShowAddFriend(true)} />
        )}
        {showAddFriend && <AddFriendModal onClose={() => setShowAddFriend(false)} />}
        {showProfile && <ProfileModal onClose={() => setShowProfile(false)} />}
        {showCreateGroup && <CreateGroupModal onClose={() => setShowCreateGroup(false)} />}
      </div>
    </div>
  );
}
