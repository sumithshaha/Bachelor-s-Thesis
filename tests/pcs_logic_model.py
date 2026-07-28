"""
Faithful model of the PCS control logic I added. Fidelity fixes vs v1:
 - Flagging a peer DROPS its session (m_crypto.dropSession) and BLOCKS sends to
   it (the verification gate). So a gated peer is not in `sessions`, cannot have
   sent>0, and cannot be pinged. Confirm re-bootstraps a fresh (sendable) chain.
 - A responder's send chain becomes alive ONLY via the inbound opening frame,
   which performs a DH ratchet -> that same frame HEALS the chain. So "becomes
   sendable" is modelled as an inbound heal (clears outstanding, drops any moot
   heal-pending, drains owed pongs).
Tests the three safety properties of the ADDED code:
 (A) reestablishPcsForAll()/kick block(3) NEVER emit a rekey to a gated peer,
 (B) m_healPending is bounded and fully cleared by logout,
 (C) the kick timer still falls silent (no spin introduced by block(3)).
"""
import random
KICK_MAX = 8

class Model:
    def __init__(self):
        self.connected=False
        self.sessions=set(); self.sendable={}
        self.flagged=set(); self.bilateral=set()
        self.sent=dict(); self.outstanding=set(); self.pongOwed=set()
        self.healPending=set(); self.kickTries=0; self.kickArmed=False
        self.emitted_to_gated=0   # property (A) counter

    def _tx(self,p): return self.connected and self.sendable.get(p,False)
    def _gate(self,p): return p in self.flagged or p in self.bilateral
    def _emit(self,p):
        if self._gate(p): self.emitted_to_gated+=1   # must stay 0
        self.outstanding.add(p)

    def reestablishPcsForAll(self):
        for p in list(self.sessions):
            if self._gate(p): continue
            if p in self.outstanding: continue
            if self._tx(p): self._emit(p); self.healPending.discard(p)
            else: self.healPending.add(p)
        if self.healPending: self.kickTries=0; self.kickArmed=True

    def kickRekey(self):
        if not self.connected: self.kickArmed=False; return
        still=False
        for p in list(self.sent.keys()):
            if self.sent.get(p,0)>0 and p not in self.outstanding and p in self.sessions:
                if self._tx(p): self._emit(p)
                else: still=True
        for p in list(self.pongOwed):
            if p in self.sessions and self._tx(p): self.pongOwed.discard(p)
            else: still=True
        for p in list(self.healPending):            # block (3) - my addition
            if self._gate(p) or p in self.outstanding: self.healPending.discard(p); continue
            if p in self.sessions and self._tx(p): self._emit(p); self.healPending.discard(p)
            else: still=True
        pong=any(p in self.sessions for p in self.pongOwed)
        if pong: self.kickTries=0; self.kickArmed=True
        elif still and (self.kickTries+1)<KICK_MAX: self.kickTries+=1; self.kickArmed=True
        else: self.kickTries=0; self.kickArmed=False

    def kick_quiesce(self,mx=1000):
        t=0
        while self.kickArmed and t<mx: self.kickRekey(); t+=1
        return t

    def inbound_heal(self,p):     # noteInboundFrom + reviving DH ratchet
        self.sent[p]=0; self.outstanding.discard(p); self.healPending.discard(p)
        self.pongOwed.discard(p)
    def recv_ping(self,p):
        if p in self.sessions:
            self.pongOwed.add(p)
            if self._tx(p): self.pongOwed.discard(p)
            else: self.kickTries=0; self.kickArmed=True
    def flag(self,p):             # flagKeyChange: drop session + gate + resetPcs
        self.flagged.add(p); self.bilateral.add(p)
        self.sessions.discard(p); self.sendable[p]=False
        self.sent.pop(p,None); self.outstanding.discard(p)   # resetPcsFor (pongOwed preserved)
        self.healPending.discard(p)
    def confirm(self,p):          # acknowledge: re-bootstrap fresh sendable chain
        self.flagged.discard(p); self.bilateral.discard(p)
        self.sent.pop(p,None); self.outstanding.discard(p)
        self.sessions.add(p); self.sendable[p]=True
    def logout(self):
        self.sent.clear(); self.outstanding.clear(); self.pongOwed.clear()
        self.healPending.clear(); self.kickTries=0; self.kickArmed=False

def fuzz(trials=40000, seed=11):
    random.seed(seed)
    peers=["a","b","c","d"]
    A=B=C=0
    for _ in range(trials):
        m=Model()
        for p in peers:
            if random.random()<0.7: m.sessions.add(p); m.sendable[p]=True
        m.connected=True
        for _ in range(random.randint(6,30)):
            op=random.choice(["drop","up","unlock","relogin","flag","confirm",
                              "peer_ping","reply","send","send_off","chain_alive","logout"])
            if op=="drop": m.connected=False
            elif op=="up": m.connected=True; m.kick_quiesce()
            elif op=="unlock":
                if m.connected: m.reestablishPcsForAll(); m.kick_quiesce()
            elif op=="relogin":
                if m.connected: m.reestablishPcsForAll(); m.kick_quiesce()
            elif op=="flag": m.flag(random.choice(peers))
            elif op=="confirm":
                p=random.choice(peers)
                if p in m.flagged: m.confirm(p); m.kick_quiesce()
            elif op=="peer_ping": m.recv_ping(random.choice(peers)); m.kick_quiesce()
            elif op=="reply": m.inbound_heal(random.choice(peers))
            elif op=="send":
                p=random.choice(peers)
                if p in m.sessions and not m._gate(p): m.sent[p]=m.sent.get(p,0)+1  # gate blocks sends
            elif op=="send_off":
                p=random.choice(peers); m.sendable[p]=False
            elif op=="chain_alive":                     # responder chain revived by inbound
                p=random.choice(peers)
                if p in m.sessions: m.sendable[p]=True; m.inbound_heal(p); m.kick_quiesce()
            elif op=="logout": m.logout()
            # (A) never a live ping to a gated peer
            A += m.emitted_to_gated; m.emitted_to_gated=0
            # (B) healPending bounded (subset of peer universe) and disjoint from gated
            if any(p in m.flagged for p in m.healPending): B+=1
            if len(m.healPending)>len(peers): B+=1
        # (C) settle: connected, all chains alive -> kick must fully drain and stop
        m.connected=True
        for p in peers: m.sendable[p]=True
        # a live chain implies the reviving inbound already healed; emulate that,
        # then let the kick drain any remaining count-rule pings/pongs.
        for p in list(m.healPending):
            if p in m.sessions: m.inbound_heal(p)
        ticks=m.kick_quiesce(mx=100)
        if m.kickArmed: C+=1                      # never still spinning
        # after settle, logout must empty everything
        m.logout()
        if (m.sent or m.outstanding or m.pongOwed or m.healPending or m.kickArmed): C+=1
    return A,B,C

A,B,C = fuzz()
print(f"(A) rekeys emitted to a gated peer:        {A}")
print(f"(B) healPending gated/overflow violations: {B}")
print(f"(C) kick spins / logout-not-empty:         {C}")
print("LOGIC OK" if (A==0 and B==0 and C==0) else "LOGIC FOUND ISSUES")
