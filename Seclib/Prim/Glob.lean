/-! Vendor-neutral case folding, glob pattern matching, and string lemmas.
No cloud provider noun appears in this module. -/

def toLowerStr (s : String) : String :=
  s.map Char.toLower

def matchPatternGo (ps vs : List Char) : Bool :=
  match ps, vs with
  | [], [] => true
  | [], _ :: _ => false
  | ['*'], _ => true
  | '*' :: ps', vs =>
    (matchPatternGo ps' vs) ||
    match vs with
    | [] => false
    | _ :: vs' => matchPatternGo ('*' :: ps') vs'
  | '?' :: ps', _ :: vs => matchPatternGo ps' vs
  | '?' :: _, [] => false
  | p :: ps', v :: vs => p == v && matchPatternGo ps' vs
  | _ :: _, [] => false
  termination_by (ps.length + vs.length, vs.length)
  decreasing_by
    all_goals simp only [List.length_cons]; omega

def matchPattern (pattern : String) (value : String) : Bool :=
  matchPatternGo pattern.toList value.toList

def ciEq (s₁ s₂ : String) : Bool :=
  toLowerStr s₁ == toLowerStr s₂

theorem ciEq_toLowerStr (s s' : String) (h : ciEq s s' = true) :
    toLowerStr s = toLowerStr s' := by
  simp [ciEq] at h; exact h

theorem matchPatternGo_literal_eq (ps vs : List Char)
    (hno_star : '*' ∉ ps) (hno_q : '?' ∉ ps)
    (h : matchPatternGo ps vs = true) :
    ps = vs := by
  induction ps, vs using matchPatternGo.induct <;> simp_all [List.mem_cons, matchPatternGo]

theorem matchPattern_literal_mp (p s : String)
    (hno_star : '*' ∉ p.toList) (hno_q : '?' ∉ p.toList)
    (h : matchPattern p s = true) :
    ciEq p s = true := by
  unfold matchPattern at h
  have hlist := matchPatternGo_literal_eq _ _ hno_star hno_q h
  have heq := String.ext hlist
  subst heq; simp [ciEq]

theorem matchPattern_cs_literal_eq (p s : String)
    (hno_star : '*' ∉ p.toList) (hno_q : '?' ∉ p.toList)
    (h : matchPattern p s = true) : p = s := by
  unfold matchPattern at h
  exact String.ext (matchPatternGo_literal_eq p.toList s.toList hno_star hno_q h)

theorem toLower_eq_star (c : Char) (h : c.toLower = '*') : c = '*' := by
  revert h; unfold Char.toLower; split
  · rename_i hup; intro h; exfalso
    rw [Char.ext_iff] at h
    have h_nat := congrArg UInt32.toNat h
    rw [UInt32.toNat_add, UInt32.toNat_sub] at h_nat
    obtain ⟨hge, hle⟩ := hup
    rw [GE.ge, UInt32.le_iff_toNat_le] at hge; rw [UInt32.le_iff_toNat_le] at hle
    have : 'A'.val.toNat = 65 := by decide
    have : 'Z'.val.toNat = 90 := by decide
    have : 'a'.val.toNat = 97 := by decide
    have : '*'.val.toNat = 42 := by decide
    simp_all; omega
  · exact fun h => h

theorem toLower_eq_question (c : Char) (h : c.toLower = '?') : c = '?' := by
  revert h; unfold Char.toLower; split
  · rename_i hup; intro h; exfalso
    rw [Char.ext_iff] at h
    have h_nat := congrArg UInt32.toNat h
    rw [UInt32.toNat_add, UInt32.toNat_sub] at h_nat
    obtain ⟨hge, hle⟩ := hup
    rw [GE.ge, UInt32.le_iff_toNat_le] at hge; rw [UInt32.le_iff_toNat_le] at hle
    have : 'A'.val.toNat = 65 := by decide
    have : 'Z'.val.toNat = 90 := by decide
    have : 'a'.val.toNat = 97 := by decide
    have : '?'.val.toNat = 63 := by decide
    simp_all; omega
  · exact fun h => h
