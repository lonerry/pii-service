#!/usr/bin/env python3
"""Patch privacy-mask-frontend bundle: restore, highlights, mask mode."""
from __future__ import annotations

from pathlib import Path

ROOT = Path("/home/lonerry/privacy-mask-frontend/dist")
DST = ROOT / "assets/index-restore-v6.js"
INDEX = ROOT / "index.html"


def _load_source() -> str:
    for name in ("index-restore-v4.js", "index-BbNWkz_s.js"):
        path = ROOT / "assets" / name
        if path.exists():
            return path.read_text(encoding="utf-8")
    raise SystemExit("frontend bundle not found")


def main() -> None:
    s = _load_source()

    e1_old = "const R=_.types??_.entities??_.detected_entities??_.pii_entities"
    e1_new = "const R=_.entities??_.types??_.detected_entities??_.pii_entities"
    if e1_old in s:
        s = s.replace(e1_old, e1_new, 1)

    if "X-Mask-Mode" not in s:
        s = s.replace("async function vm(_,V,R)", "async function vm(_,V,R,U)", 1)
        s = s.replace(
            'headers:{"Content-Type":"application/json","X-System-Id":_}',
            'headers:{"Content-Type":"application/json","X-System-Id":_,"X-Mask-Mode":U||"format"}',
            1,
        )

    if "direction:A.direction" not in s:
        s = s.replace(
            "return{...M,elapsedMs:M.elapsedMs??performance.now()-m}",
            "return{...M,elapsedMs:M.elapsedMs??performance.now()-m,direction:A.direction}",
            1,
        )

    if 'sessionStorage.setItem("pii:last"' not in s:
        s = s.replace(
            "Ol(O),ql(O1($,Z.text,Z.entities))",
            'Ol(O),sessionStorage.setItem("pii:last",JSON.stringify({system:R,id:O,masked:Z.text})),ql(O1($,Z.text,Z.entities))',
            1,
        )

    s = s.replace(
        "ql(O1($,Z.text,Z.entities))",
        "ql(Z.entities?.length?Z.entities:O1($,Z.text,Z.entities))",
    )

    restore_new = (
        'try{const st=JSON.parse(sessionStorage.getItem("pii:last")||"null"),'
        "mid=st&&st.id===j?st.masked:w,sys=st&&st.id===j?st.system:R,"
        'O=await vm(sys,mid,j,Ul);if(O.direction!=="demask")throw new Error('
        '"Не удалось восстановить текст. Защитите данные заново и повторите.");'
        "S(O.text),el(O.text),bl(O.text),M(!0)}"
    )
    for restore_old in (
        'try{const st=JSON.parse(sessionStorage.getItem("pii:last")||"null"),mid=st&&st.id===j?st.masked:w,sys=st&&st.id===j?st.system:R,O=await vm(sys,mid,j);if(O.direction!=="demask")throw new Error("Не удалось восстановить текст. Защитите данные заново и повторите.");S(O.text),el(O.text),bl(O.text),M(!0)}',
        'try{const O=await vm(R,w,j);if(O.direction!=="demask")throw new Error("Не удалось восстановить текст. Защитите данные заново и повторите.");S(O.text),el(O.text),bl(O.text),M(!0)}',
        "try{const O=await vm(R,w,j);S(O.text),M(!0)}",
    ):
        if restore_old in s:
            s = s.replace(restore_old, restore_new, 1)
            break

    if "[Ul,Il]=kl.useState" not in s:
        s = s.replace("[Ml,Nt]=kl.useState(null),", '[Ml,Nt]=kl.useState(null),[Ul,Il]=kl.useState("format"),', 1)
        s = s.replace("const Z=await vm(R,$,O);", "const Z=await vm(R,$,O,Ul);", 1)
        mode_old = (
            'b.jsxs("label",{children:["Режим",b.jsx("select",{value:R,onChange:O=>D(O.target.value),'
            "children:Object.keys(_).map(O=>b.jsx(\"option\",{value:O,children:O},O))})]})]}),"
        )
        mode_new = (
            'b.jsxs("label",{children:["Режим",b.jsx("select",{value:R,onChange:O=>D(O.target.value),'
            "children:Object.keys(_).map(O=>b.jsx(\"option\",{value:O,children:O},O))})]}),"
            'b.jsxs("label",{children:["Маскирование",b.jsxs("select",{value:Ul,onChange:O=>Il(O.target.value),'
            'children:[b.jsx("option",{value:"format",children:"Форматное"}),'
            'b.jsx("option",{value:"synthetic",children:"Синтетика"})]})]})]}),'
        )
        if mode_old in s:
            s = s.replace(mode_old, mode_new, 1)

    DST.write_text(s, encoding="utf-8")
    import re

    html = INDEX.read_text(encoding="utf-8")
    html = re.sub(
        r'src="/assets/index-[^"]+\.js"',
        'src="/assets/index-restore-v6.js"',
        html,
        count=1,
    )
    INDEX.write_text(html, encoding="utf-8")
    print("patched", DST)


if __name__ == "__main__":
    main()
