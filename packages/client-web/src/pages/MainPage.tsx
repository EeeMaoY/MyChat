/** 主界面：好友申请/恢复/安全横幅 + 桌面双栏（会话列表 + 聊天窗），窄屏单列切换（CSS media query）。 */
import { useState } from "react";

import { openChat, openChatView, openTimeline, useAppState } from "../lib/app";

import AddFriendModal from "../components/AddFriendModal";
import ChatPanel from "../components/ChatPanel";
import ContactSidebar from "../components/ContactSidebar";
import CreateGroupModal from "../components/CreateGroupModal";
import GroupMembersModal from "../components/GroupMembersModal";
import FriendRequestBanner from "../components/FriendRequestBanner";
import PassphraseModal from "../components/PassphraseModal";
import ProfileModal from "../components/ProfileModal";
import RecoveryRequestBanner from "../components/RecoveryRequestBanner";
import SecurityBanner from "../components/SecurityBanner";
import TimelinePage from "../components/TimelinePage";

export default function MainPage() {
  const state = useAppState();
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [membersGroupId, setMembersGroupId] = useState<string | null>(null);
  const [showPassphrase, setShowPassphrase] = useState(false);

  return (
    <div className="main-root">
      <FriendRequestBanner />
      <RecoveryRequestBanner />
      <SecurityBanner onSetup={() => setShowPassphrase(true)} />
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
          <ChatPanel
            onBack={() => openChat(null)}
            onAddFriend={() => setShowAddFriend(true)}
            onOpenMembers={(groupId) => setMembersGroupId(groupId)}
          />
        )}
        {membersGroupId !== null && <GroupMembersModal groupId={membersGroupId} onClose={() => setMembersGroupId(null)} />}
        {showAddFriend && <AddFriendModal onClose={() => setShowAddFriend(false)} />}
        {showProfile && (
          <ProfileModal onClose={() => setShowProfile(false)} onSetupPassphrase={() => { setShowProfile(false); setShowPassphrase(true); }} />
        )}
        {showCreateGroup && <CreateGroupModal onClose={() => setShowCreateGroup(false)} />}
        {showPassphrase && <PassphraseModal initialSetup onClose={() => setShowPassphrase(false)} />}
      </div>
    </div>
  );
}
