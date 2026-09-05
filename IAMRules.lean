import Aesop
import Seclib.Prim
import Seclib.Prim.Glob
import Seclib.Prim.Context
import IamExplainer.Condition
import IamExplainer.Emit
import IamExplainer.Layers

/-! Aesop domain rules for IAM proof automation. -/

-- Safe: Tri and Effect case enumeration
attribute [aesop safe cases] Tri Effect

-- Safe: constructor introduction
attribute [aesop safe constructors] And

-- Norm: key equivalences as simp lemmas
attribute [aesop norm simp] Tri.and_eq_t

-- Unsafe: domain lemmas
attribute [aesop unsafe 75% apply] Tri.and_tu
attribute [aesop unsafe 75% apply] evalCond_noContext_tu
attribute [aesop unsafe 75% apply] evalCond_noContext_T_imp
