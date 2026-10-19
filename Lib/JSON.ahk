#Requires AutoHotkey v2.0
;==============================================================================
; FILE   : <ROOT>\Lib\JSON.ahk
; PART OF: Automation & Protection Toolkit
; ROLE   : Dependency-free JSON for AHK v2. API-compatible with thqby's
;          JSON.ahk (JSON.parse / JSON.stringify) so a battle-tested vendor
;          library can be dropped in as a replacement without call-site
;          changes (see README "Third-party libraries").
; MAPPING: JSON object -> Map, JSON array -> Array, JSON null -> "" (empty
;          string; documented limitation), numbers -> AHK Integer/Float,
;          strings escaped per RFC 8259. Parser is depth-capped (128) and
;          throws ValueError with the offset on malformed input.
; NOTE   : Standalone — must not depend on Core.ahk.
;==============================================================================

class JSON {
    static parse(str) {
        r := _JsonReader(str)
        v := r.ReadValue()
        r.SkipWs()
        if !r.Eof()
            throw ValueError("JSON: trailing data at offset " . r.Offset)
        return v
    }

    static stringify(obj, indent := 0) {
        w := _JsonWriter(indent)
        return w.Write(obj)
    }
}

;------------------------------------------------------------------------------
; Parser (recursive descent).
;------------------------------------------------------------------------------
class _JsonReader {
    src := "", pos := 1, depth := 0

    __New(src) {
        this.src := src
    }

    Offset => this.pos

    Eof() {
        return this.pos > StrLen(this.src)
    }

    Peek() {
        return SubStr(this.src, this.pos, 1)
    }

    Next() {
        c := this.Peek()
        this.pos++
        return c
    }

    SkipWs() {
        while !this.Eof() {
            c := this.Peek()
            if c == "" || !InStr(" `t`r`n", c)
                break
            this.pos++
        }
    }

    Expect(c) {
        if this.Eof() || this.Next() != c
            throw ValueError("JSON: expected " . c . " at offset " . this.pos)
    }

    ReadValue() {
        this.depth++
        if this.depth > 128
            throw ValueError("JSON: nesting too deep (limit 128)")
        this.SkipWs()
        if this.pos > StrLen(this.src)
            throw ValueError("JSON: unexpected end of input")
        c := this.Peek()
        v := ""
        if c == "{"
            v := this.ReadObject()
        else if c == "["
            v := this.ReadArray()
        else if c == Chr(34)
            v := this.ReadString()
        else if c == "t" || c == "f" || c == "n"
            v := this.ReadLiteral()
        else
            v := this.ReadNumber()
        this.depth--
        return v
    }

    ReadObject() {
        this.Expect("{")
        o := Map()
        this.SkipWs()
        if this.Peek() == "}" {
            this.Next()
            return o
        }
        Loop {
            this.SkipWs()
            k := this.ReadString()
            this.SkipWs()
            this.Expect(":")
            o[k] := this.ReadValue()
            this.SkipWs()
            c := this.Next()
            if c == "}"
                return o
            if c != ","
                throw ValueError("JSON: expected ',' or '}' in object at offset " . this.pos)
        }
    }

    ReadArray() {
        this.Expect("[")
        a := []
        this.SkipWs()
        if this.Peek() == "]" {
            this.Next()
            return a
        }
        Loop {
            a.Push(this.ReadValue())
            this.SkipWs()
            c := this.Next()
            if c == "]"
                return a
            if c != ","
                throw ValueError("JSON: expected ',' or ']' in array at offset " . this.pos)
        }
    }

    ReadString() {
        this.Expect(Chr(34))
        out := ""
        Loop {
            if this.Eof()
                throw ValueError("JSON: unterminated string")
            c := this.Next()
            if c == Chr(34)
                return out
            if c == Chr(92) {
                if this.Eof()
                    throw ValueError("JSON: dangling escape")
                e := this.Next()
                switch e {
                    case Chr(34): out .= Chr(34)
                    case Chr(92): out .= "\\"
                    case "/":  out .= "/"
                    case "b":  out .= "`b"
                    case "f":  out .= "`f"
                    case "n":  out .= "`n"
                    case "r":  out .= "`r"
                    case "t":  out .= "`t"
                    case "u":
                        u := SubStr(this.src, this.pos, 4)
                        if !RegExMatch(u, "i)^[0-9a-f]{4}$")
                            throw ValueError("JSON: bad \u escape at offset " . this.pos)
                        this.pos += 4
                        cp := Integer("0x" . u)
                        ; Combine UTF-16 surrogate pairs into one astral char.
                        if cp >= 0xD800 && cp <= 0xDBFF && SubStr(this.src, this.pos, 2) == "\u" {
                            u2 := SubStr(this.src, this.pos + 2, 4)
                            if RegExMatch(u2, "i)^[0-9a-f]{4}$") {
                                lo := Integer("0x" . u2)
                                if lo >= 0xDC00 && lo <= 0xDFFF {
                                    this.pos += 6
                                    cp := 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                                }
                            }
                        }
                        out .= Chr(cp)
                    default:
                        throw ValueError("JSON: unknown escape at offset " . this.pos)
                }
            } else
                out .= c
        }
    }

    ReadLiteral() {
        ; "true" | "false" | "null". null maps to "" (documented limitation).
        if SubStr(this.src, this.pos, 4) == "true" {
            this.pos += 4
            return 1
        }
        if SubStr(this.src, this.pos, 5) == "false" {
            this.pos += 5
            return 0
        }
        if SubStr(this.src, this.pos, 4) == "null" {
            this.pos += 4
            return ""
        }
        throw ValueError("JSON: bad literal at offset " . this.pos)
    }

    ReadNumber() {
        if !RegExMatch(SubStr(this.src, this.pos), "^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?", &m)
            throw ValueError("JSON: bad number at offset " . this.pos)
        this.pos += StrLen(m[0])
        return Number(m[0])
    }
}

;------------------------------------------------------------------------------
; Writer.
;------------------------------------------------------------------------------
class _JsonWriter {
    indent := 0, lvl := 0

    __New(indent) {
        this.indent := Integer(indent) < 0 ? 0 : Integer(indent)
    }

    Write(v) {
        if IsObject(v) {
            if v is Map
                return this.WriteMap(v)
            if v is Array
                return this.WriteArray(v)
            ; Plain object: treat its own properties as a Map.
            m := Map()
            for k, val in v.OwnProps()
                m[k] := val
            return this.WriteMap(m)
        }
        if v is Integer || v is Float
            return String(v)
        return this.Esc(String(v))
    }

    WriteMap(m) {
        if m.Count == 0
            return "{}"
        this.lvl++
        nl := this._Nl()
        nlPrev := this._Nl(-1)
        parts := []
        for k, v in m
            parts.Push(nl . this.Esc(String(k)) . (this.indent > 0 ? ": " : ":") . this.Write(v))
        this.lvl--
        return "{" . _JsonJoin(parts, ",") . nlPrev . "}"
    }

    WriteArray(a) {
        if a.Length == 0
            return "[]"
        this.lvl++
        nl := this._Nl()
        nlPrev := this._Nl(-1)
        parts := []
        for v in a
            parts.Push(nl . this.Write(v))
        this.lvl--
        return "[" . _JsonJoin(parts, ",") . nlPrev . "]"
    }

    _Nl(back := 0) {
        if this.indent == 0
            return ""
        return "`n" . _JsonRep(" ", this.indent * (this.lvl + back))
    }

    Esc(s) {
        out := Chr(34)
        Loop Parse s {
            c := A_LoopField
            if c == Chr(34)
                out .= Chr(92) . Chr(34)
            else if c == Chr(92)
                out .= "\\"
            else if c == "`n"
                out .= "\n"
            else if c == "`r"
                out .= "\r"
            else if c == "`t"
                out .= "\t"
            else if c == "`b"
                out .= "\b"
            else if c == "`f"
                out .= "\f"
            else if Ord(c) < 32
                out .= Format("\u{:04x}", Ord(c))
            else
                out .= c
        }
        return out . Chr(34)
    }
}

_JsonJoin(arr, sep) {
    s := ""
    for i, v in arr
        s .= (i == 1 ? "" : sep) . String(v)
    return s
}

_JsonRep(s, n) {
    out := ""
    Loop n
        out .= s
    return out
}
