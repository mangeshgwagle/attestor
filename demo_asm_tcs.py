import sys
sys.path.insert(0, "detector")
import hashlib, detect, case_file42 as cf

print("=== LANGUAGE DETECTION (NASM = x86-64) ===")
for f in ["exploit.asm", "exploit.nasm", "exploit.s", "priv.mlc", "priv.hlasm"]:
    print(f"  {f:15} -> {detect.language_for(f)}")

X86_MALICIOUS = """section .text
    mov rsp, rax          ; stack pivot -> asm-stack-pivot
    mov rax, 59
    syscall               ; asm-direct-execve
    int 0x80              ; asm-legacy-int80
""" + "    nop\n"*20 + '    .section .data,"awx"\n'

NASM_CLEAN = """section .text
global _start
_start:
    mov rax, 1
    mov rdi, 1
    syscall
    ret
    .section .note.GNU-stack,"",@progbits
"""

HLASM_PRIV = """MAIN     CSECT
         MODESET KEY=ZERO            GO AUTHORISED
         SPKA  0(R2)                 SET PSW KEY
         SVC   120                   RAW SUPERVISOR CALL
         EX    R3,MOVEIT             VARIABLE LENGTH MOVE
"""

HLASM_CLEAN = """MAIN     CSECT
         LA    R1,4095*2             ARITHMETIC USES STAR
         MVC   TARGET(80),SOURCE     FIXED LENGTH MOVE
         BR    R14
"""

def fired(src, lang):
    return {r.rule for r in detect.scan_source(src, "t", lang, deep=True) if r.rule.startswith(("asm-","hlasm-"))}

print("\n=== x86-64 (NASM) SCAN ===")
print(" malicious:", fired(X86_MALICIOUS, "asm"))
print(" clean   :", fired(NASM_CLEAN, "asm"))
print(" comment trap (must be empty):", fired('; mov rsp, rax would be a stack pivot\n    ret\n', "asm"))

print("\n=== IBM System/360 HLASM SCAN ===")
print(" privileged:", fired(HLASM_PRIV, "hlasm"))
print(" clean     :", fired(HLASM_CLEAN, "hlasm"))
print(" data trap (MODESET in DC must be empty):", fired("MAIN     CSECT\n         DC    C'MODESET KEY=ZERO'   THIS IS DATA\n         BR    R14\n", "hlasm"))

print("\n=== NASM == is x86-64 ===")
print(" .nasm file:", fired(X86_MALICIOUS, "asm"), "same engine as .asm")

print("\n=== CASE FILE FOR ASM FINDING (TCS-ready) ===")
sha = hashlib.sha256(X86_MALICIOUS.encode()).hexdigest()
case = cf.open_case(subject_path="src/payload.asm", subject_sha256=sha, rule="asm-direct-execve", summary="x86-64 syscall execve with prior stack pivot")
case = cf.append(case, stage="discovery", basis=cf.MEASURED, summary="asm-direct-execve + asm-stack-pivot both fired", evidence={"path": "src/payload.asm", "rules": ["asm-stack-pivot","asm-direct-execve"], "source_sha256": sha})
case = cf.append(case, stage="validation", basis=cf.MEASURED, summary="listing disassembled, syscalls confirmed", evidence={"reproduced": True})
case = cf.append(case, stage="exploitability", basis=cf.MEASURED, summary="no sanitizer, reachable if loaded", evidence={"triage": "no-static-path-from-a-discovered-entrypoint", "runtime_exploitability": "unverified"})
case = cf.append(case, stage="remediation", basis=cf.MEASURED, summary="remove direct syscall, use libc wrapper with allowlist", evidence={"diff_sha256": "e"*64})
case = cf.append(case, stage="regression", basis=cf.MEASURED, summary="assembly test fails before, passes after", evidence={"fails_before_fix": True, "passes_after_fix": True})
case = cf.append(case, stage="documentation", basis=cf.MEASURED, summary="advisory for z/TCS SOC", evidence={"advisory_id": "AT-ASM-2026-001"})
print(cf.render(case))
ok,_ = cf.verify(case)
print("verify:", ok, "proven:", cf.is_proven(case))

print("\n=== HLASM CASE ===")
sha2 = hashlib.sha256(HLASM_PRIV.encode()).hexdigest()
c2 = cf.open_case(subject_path="src/priv.mlc", subject_sha256=sha2, rule="hlasm-authorized-mode", summary="HLASM MODESET KEY=ZERO privileged")
c2 = cf.append(c2, stage="discovery", basis=cf.MEASURED, summary="hlasm-authorized-mode fired", evidence={"path": "src/priv.mlc", "line": 2})
c2 = cf.append(c2, stage="remediation", basis=cf.MEASURED, summary="remove MODESET, run authorized", evidence={"diff_sha256": "f"*64})
c2 = cf.append(c2, stage="regression", basis=cf.MEASURED, summary="priv test fails before", evidence={"fails_before_fix": True, "passes_after_fix": True})
print(cf.render(c2))
print("hlasm proven:", cf.is_proven(c2))
