;; ============================================================================
;; version.inc -- SINGLE SOURCE OF TRUTH for the node's wire identity.
;;
;; Everything this node claims on the wire -- its application version, the
;; user-agent string it advertises in the P2P version handshake, and the
;; Bitcoin protocol version it speaks -- derives from the values in this ONE
;; file. Nothing else should hardcode these numbers.
;;
;; Consumption:
;;   * ASM (.asm)   -> `%include "version.inc"` at the top of the section, then
;;                     use NODE_UA_STRING / NODE_UA_LEN / NODE_PROTOCOL_VER.
;;                     NODE_UA_LEN and NODE_UA_STRING are DERIVED at assembly
;;                     time via %strlen/%strcat, so the length byte can never
;;                     drift from the string.
;;   * C   -> the Makefile regenerates version_gen.h from this file; C code
;;            #includes that and reads NODE_VERSION_*, NODE_PROTOCOL_VER,
;;            NODE_UA_STRING_LEN, NODE_UA_STRING.
;;
;; IMPORTANT: keep this the single source. To bump the version, edit ONLY the
;; %define lines below. Do not hand-edit NODE_UA_* derived values.
;; ============================================================================

; ---- application version (semantic) ----------------------------------------
%define NODE_VERSION_MAJOR 0
%define NODE_VERSION_MINOR 0
%define NODE_VERSION_PATCH 1

; ---- Bitcoin wire protocol version (do not bump casually: it is a wire
;      contract, not the app version). 70016 == Bitcoin Core 0.19-era wire. ---
%define NODE_PROTOCOL_VER 70016

; ---- user-agent components -------------------------------------------------
%define NODE_UA_PREFIX "/BitcoinMachineCode:"
%define NODE_UA_SUFFIX "/"

; ---- derived (DO NOT EDIT BY HAND) -----------------------------------------
; Convert the numeric version components to strings so they can be assembled
; into the user-agent string.
%defstr NODE_MAJ_S NODE_VERSION_MAJOR
%defstr NODE_MIN_S NODE_VERSION_MINOR
%defstr NODE_PAT_S NODE_VERSION_PATCH
; Build the full user-agent wire string: /BitcoinMachineCode:0.0.1/
%strcat NODE_UA_STRING NODE_UA_PREFIX, NODE_MAJ_S, ".", NODE_MIN_S, ".", NODE_PAT_S, NODE_UA_SUFFIX
; Length of that string -- used as the CompactSize-prefix byte on the wire and
; to size the version payload. Derived, so it always matches the string.
%strlen NODE_UA_LEN NODE_UA_STRING
