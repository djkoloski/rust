//! There are four type combiners: [Equate], [Sub], [Lub], and [Glb].
//! Each implements the trait [TypeRelation] and contains methods for
//! combining two instances of various things and yielding a new instance.
//! These combiner methods always yield a `Result<T>`. To relate two
//! types, you can use `infcx.at(cause, param_env)` which then allows
//! you to use the relevant methods of [At](super::at::At).
//!
//! Combiners mostly do their specific behavior and then hand off the
//! bulk of the work to [InferCtxt::super_combine_tys] and
//! [InferCtxt::super_combine_consts].
//!
//! Combining two types may have side-effects on the inference contexts
//! which can be undone by using snapshots. You probably want to use
//! either [InferCtxt::commit_if_ok] or [InferCtxt::probe].
//!
//! On success, the  LUB/GLB operations return the appropriate bound. The
//! return value of `Equate` or `Sub` shouldn't really be used.
//!
//! ## Contravariance
//!
//! We explicitly track which argument is expected using
//! [TypeRelation::a_is_expected], so when dealing with contravariance
//! this should be correctly updated.

use super::equate::Equate;
use super::glb::Glb;
use super::lub::Lub;
use super::sub::Sub;
use super::{DefineOpaqueTypes, InferCtxt, TypeTrace};
use crate::infer::generalize::{self, CombineDelegate, Generalization};
use crate::traits::{Obligation, PredicateObligations};
use rustc_middle::infer::canonical::OriginalQueryValues;
use rustc_middle::infer::unify_key::{ConstVarValue, ConstVariableValue};
use rustc_middle::infer::unify_key::{ConstVariableOrigin, ConstVariableOriginKind};
use rustc_middle::ty::error::{ExpectedFound, TypeError};
use rustc_middle::ty::relate::{RelateResult, TypeRelation};
use rustc_middle::ty::{self, AliasKind, InferConst, ToPredicate, Ty, TyCtxt, TypeVisitableExt};
use rustc_middle::ty::{IntType, UintType};
use rustc_span::DUMMY_SP;

#[derive(Clone)]
pub struct CombineFields<'infcx, 'tcx> {
    pub infcx: &'infcx InferCtxt<'tcx>,
    pub trace: TypeTrace<'tcx>,
    pub cause: Option<ty::relate::Cause>,
    pub param_env: ty::ParamEnv<'tcx>,
    pub obligations: PredicateObligations<'tcx>,
    pub define_opaque_types: DefineOpaqueTypes,
}

#[derive(Copy, Clone, Debug)]
pub enum RelationDir {
    SubtypeOf,
    SupertypeOf,
    EqTo,
}

impl<'tcx> InferCtxt<'tcx> {
    pub fn super_combine_tys<R>(
        &self,
        relation: &mut R,
        a: Ty<'tcx>,
        b: Ty<'tcx>,
    ) -> RelateResult<'tcx, Ty<'tcx>>
    where
        R: ObligationEmittingRelation<'tcx>,
    {
        let a_is_expected = relation.a_is_expected();
        debug_assert!(!a.has_escaping_bound_vars());
        debug_assert!(!b.has_escaping_bound_vars());

        match (a.kind(), b.kind()) {
            // Relate integral variables to other types
            (&ty::Infer(ty::IntVar(a_id)), &ty::Infer(ty::IntVar(b_id))) => {
                self.inner
                    .borrow_mut()
                    .int_unification_table()
                    .unify_var_var(a_id, b_id)
                    .map_err(|e| int_unification_error(a_is_expected, e))?;
                Ok(a)
            }
            (&ty::Infer(ty::IntVar(v_id)), &ty::Int(v)) => {
                self.unify_integral_variable(a_is_expected, v_id, IntType(v))
            }
            (&ty::Int(v), &ty::Infer(ty::IntVar(v_id))) => {
                self.unify_integral_variable(!a_is_expected, v_id, IntType(v))
            }
            (&ty::Infer(ty::IntVar(v_id)), &ty::Uint(v)) => {
                self.unify_integral_variable(a_is_expected, v_id, UintType(v))
            }
            (&ty::Uint(v), &ty::Infer(ty::IntVar(v_id))) => {
                self.unify_integral_variable(!a_is_expected, v_id, UintType(v))
            }

            // Relate floating-point variables to other types
            (&ty::Infer(ty::FloatVar(a_id)), &ty::Infer(ty::FloatVar(b_id))) => {
                self.inner
                    .borrow_mut()
                    .float_unification_table()
                    .unify_var_var(a_id, b_id)
                    .map_err(|e| float_unification_error(relation.a_is_expected(), e))?;
                Ok(a)
            }
            (&ty::Infer(ty::FloatVar(v_id)), &ty::Float(v)) => {
                self.unify_float_variable(a_is_expected, v_id, v)
            }
            (&ty::Float(v), &ty::Infer(ty::FloatVar(v_id))) => {
                self.unify_float_variable(!a_is_expected, v_id, v)
            }

            // We don't expect `TyVar` or `Fresh*` vars at this point with lazy norm.
            (
                ty::Alias(AliasKind::Projection, _),
                ty::Infer(ty::TyVar(_) | ty::FreshTy(_) | ty::FreshIntTy(_) | ty::FreshFloatTy(_)),
            )
            | (
                ty::Infer(ty::TyVar(_) | ty::FreshTy(_) | ty::FreshIntTy(_) | ty::FreshFloatTy(_)),
                ty::Alias(AliasKind::Projection, _),
            ) if self.tcx.trait_solver_next() => {
                bug!()
            }

            (_, ty::Alias(AliasKind::Projection | AliasKind::Inherent, _))
            | (ty::Alias(AliasKind::Projection | AliasKind::Inherent, _), _)
                if self.tcx.trait_solver_next() =>
            {
                relation.register_type_relate_obligation(a, b);
                Ok(a)
            }

            // All other cases of inference are errors
            (&ty::Infer(_), _) | (_, &ty::Infer(_)) => {
                Err(TypeError::Sorts(ty::relate::expected_found(relation, a, b)))
            }

            // During coherence, opaque types should be treated as *possibly*
            // equal to each other, even if their generic params differ, as
            // they could resolve to the same hidden type, even for different
            // generic params.
            (
                &ty::Alias(ty::Opaque, ty::AliasTy { def_id: a_def_id, .. }),
                &ty::Alias(ty::Opaque, ty::AliasTy { def_id: b_def_id, .. }),
            ) if self.intercrate && a_def_id == b_def_id => {
                relation.register_predicates([ty::Binder::dummy(ty::PredicateKind::Ambiguous)]);
                Ok(a)
            }

            _ => ty::relate::super_relate_tys(relation, a, b),
        }
    }

    pub fn super_combine_consts<R>(
        &self,
        relation: &mut R,
        a: ty::Const<'tcx>,
        b: ty::Const<'tcx>,
    ) -> RelateResult<'tcx, ty::Const<'tcx>>
    where
        R: ObligationEmittingRelation<'tcx>,
    {
        debug!("{}.consts({:?}, {:?})", relation.tag(), a, b);
        debug_assert!(!a.has_escaping_bound_vars());
        debug_assert!(!b.has_escaping_bound_vars());
        if a == b {
            return Ok(a);
        }

        let a = self.shallow_resolve(a);
        let b = self.shallow_resolve(b);

        // We should never have to relate the `ty` field on `Const` as it is checked elsewhere that consts have the
        // correct type for the generic param they are an argument for. However there have been a number of cases
        // historically where asserting that the types are equal has found bugs in the compiler so this is valuable
        // to check even if it is a bit nasty impl wise :(
        //
        // This probe is probably not strictly necessary but it seems better to be safe and not accidentally find
        // ourselves with a check to find bugs being required for code to compile because it made inference progress.
        let compatible_types = self.probe(|_| {
            if a.ty() == b.ty() {
                return Ok(());
            }

            // We don't have access to trait solving machinery in `rustc_infer` so the logic for determining if the
            // two const param's types are able to be equal has to go through a canonical query with the actual logic
            // in `rustc_trait_selection`.
            let canonical = self.canonicalize_query(
                (relation.param_env(), a.ty(), b.ty()),
                &mut OriginalQueryValues::default(),
            );
            self.tcx.check_tys_might_be_eq(canonical).map_err(|_| {
                self.tcx.sess.delay_span_bug(
                    DUMMY_SP,
                    format!("cannot relate consts of different types (a={:?}, b={:?})", a, b,),
                )
            })
        });

        // If the consts have differing types, just bail with a const error with
        // the expected const's type. Specifically, we don't want const infer vars
        // to do any type shapeshifting before and after resolution.
        if let Err(guar) = compatible_types {
            // HACK: equating both sides with `[const error]` eagerly prevents us
            // from leaving unconstrained inference vars during things like impl
            // matching in the solver.
            let a_error = self.tcx.const_error(a.ty(), guar);
            if let ty::ConstKind::Infer(InferConst::Var(vid)) = a.kind() {
                return self.unify_const_variable(vid, a_error, relation.param_env());
            }
            let b_error = self.tcx.const_error(b.ty(), guar);
            if let ty::ConstKind::Infer(InferConst::Var(vid)) = b.kind() {
                return self.unify_const_variable(vid, b_error, relation.param_env());
            }

            return Ok(if relation.a_is_expected() { a_error } else { b_error });
        }

        match (a.kind(), b.kind()) {
            (
                ty::ConstKind::Infer(InferConst::Var(a_vid)),
                ty::ConstKind::Infer(InferConst::Var(b_vid)),
            ) => {
                self.inner.borrow_mut().const_unification_table().union(a_vid, b_vid);
                return Ok(a);
            }

            // All other cases of inference with other variables are errors.
            (ty::ConstKind::Infer(InferConst::Var(_)), ty::ConstKind::Infer(_))
            | (ty::ConstKind::Infer(_), ty::ConstKind::Infer(InferConst::Var(_))) => {
                bug!("tried to combine ConstKind::Infer/ConstKind::Infer(InferConst::Var)")
            }

            (ty::ConstKind::Infer(InferConst::Var(vid)), _) => {
                return self.unify_const_variable(vid, b, relation.param_env());
            }

            (_, ty::ConstKind::Infer(InferConst::Var(vid))) => {
                return self.unify_const_variable(vid, a, relation.param_env());
            }
            (ty::ConstKind::Unevaluated(..), _) | (_, ty::ConstKind::Unevaluated(..))
                if self.tcx.lazy_normalization() =>
            {
                relation.register_const_equate_obligation(a, b);
                return Ok(b);
            }
            _ => {}
        }

        ty::relate::super_relate_consts(relation, a, b)
    }

    /// Unifies the const variable `target_vid` with the given constant.
    ///
    /// This also tests if the given const `ct` contains an inference variable which was previously
    /// unioned with `target_vid`. If this is the case, inferring `target_vid` to `ct`
    /// would result in an infinite type as we continuously replace an inference variable
    /// in `ct` with `ct` itself.
    ///
    /// This is especially important as unevaluated consts use their parents generics.
    /// They therefore often contain unused substs, making these errors far more likely.
    ///
    /// A good example of this is the following:
    ///
    /// ```compile_fail,E0308
    /// #![feature(generic_const_exprs)]
    ///
    /// fn bind<const N: usize>(value: [u8; N]) -> [u8; 3 + 4] {
    ///     todo!()
    /// }
    ///
    /// fn main() {
    ///     let mut arr = Default::default();
    ///     arr = bind(arr);
    /// }
    /// ```
    ///
    /// Here `3 + 4` ends up as `ConstKind::Unevaluated` which uses the generics
    /// of `fn bind` (meaning that its substs contain `N`).
    ///
    /// `bind(arr)` now infers that the type of `arr` must be `[u8; N]`.
    /// The assignment `arr = bind(arr)` now tries to equate `N` with `3 + 4`.
    ///
    /// As `3 + 4` contains `N` in its substs, this must not succeed.
    ///
    /// See `tests/ui/const-generics/occurs-check/` for more examples where this is relevant.
    #[instrument(level = "debug", skip(self))]
    fn unify_const_variable(
        &self,
        target_vid: ty::ConstVid<'tcx>,
        ct: ty::Const<'tcx>,
        param_env: ty::ParamEnv<'tcx>,
    ) -> RelateResult<'tcx, ty::Const<'tcx>> {
        let span =
            self.inner.borrow_mut().const_unification_table().probe_value(target_vid).origin.span;
        let Generalization { value, needs_wf: _ } = generalize::generalize(
            self,
            &mut CombineDelegate { infcx: self, span, param_env },
            ct,
            target_vid,
            ty::Variance::Invariant,
        )?;

        self.inner.borrow_mut().const_unification_table().union_value(
            target_vid,
            ConstVarValue {
                origin: ConstVariableOrigin {
                    kind: ConstVariableOriginKind::ConstInference,
                    span: DUMMY_SP,
                },
                val: ConstVariableValue::Known { value },
            },
        );
        Ok(value)
    }

    fn unify_integral_variable(
        &self,
        vid_is_expected: bool,
        vid: ty::IntVid,
        val: ty::IntVarValue,
    ) -> RelateResult<'tcx, Ty<'tcx>> {
        self.inner
            .borrow_mut()
            .int_unification_table()
            .unify_var_value(vid, Some(val))
            .map_err(|e| int_unification_error(vid_is_expected, e))?;
        match val {
            IntType(v) => Ok(self.tcx.mk_mach_int(v)),
            UintType(v) => Ok(self.tcx.mk_mach_uint(v)),
        }
    }

    fn unify_float_variable(
        &self,
        vid_is_expected: bool,
        vid: ty::FloatVid,
        val: ty::FloatTy,
    ) -> RelateResult<'tcx, Ty<'tcx>> {
        self.inner
            .borrow_mut()
            .float_unification_table()
            .unify_var_value(vid, Some(ty::FloatVarValue(val)))
            .map_err(|e| float_unification_error(vid_is_expected, e))?;
        Ok(self.tcx.mk_mach_float(val))
    }
}

impl<'infcx, 'tcx> CombineFields<'infcx, 'tcx> {
    pub fn tcx(&self) -> TyCtxt<'tcx> {
        self.infcx.tcx
    }

    pub fn equate<'a>(&'a mut self, a_is_expected: bool) -> Equate<'a, 'infcx, 'tcx> {
        Equate::new(self, a_is_expected)
    }

    pub fn sub<'a>(&'a mut self, a_is_expected: bool) -> Sub<'a, 'infcx, 'tcx> {
        Sub::new(self, a_is_expected)
    }

    pub fn lub<'a>(&'a mut self, a_is_expected: bool) -> Lub<'a, 'infcx, 'tcx> {
        Lub::new(self, a_is_expected)
    }

    pub fn glb<'a>(&'a mut self, a_is_expected: bool) -> Glb<'a, 'infcx, 'tcx> {
        Glb::new(self, a_is_expected)
    }

    /// Here, `dir` is either `EqTo`, `SubtypeOf`, or `SupertypeOf`.
    /// The idea is that we should ensure that the type `a_ty` is equal
    /// to, a subtype of, or a supertype of (respectively) the type
    /// to which `b_vid` is bound.
    ///
    /// Since `b_vid` has not yet been instantiated with a type, we
    /// will first instantiate `b_vid` with a *generalized* version
    /// of `a_ty`. Generalization introduces other inference
    /// variables wherever subtyping could occur.
    #[instrument(skip(self), level = "debug")]
    pub fn instantiate(
        &mut self,
        a_ty: Ty<'tcx>,
        dir: RelationDir,
        b_vid: ty::TyVid,
        a_is_expected: bool,
    ) -> RelateResult<'tcx, ()> {
        use self::RelationDir::*;

        // Get the actual variable that b_vid has been inferred to
        debug_assert!(self.infcx.inner.borrow_mut().type_variables().probe(b_vid).is_unknown());

        // Generalize type of `a_ty` appropriately depending on the
        // direction. As an example, assume:
        //
        // - `a_ty == &'x ?1`, where `'x` is some free region and `?1` is an
        //   inference variable,
        // - and `dir` == `SubtypeOf`.
        //
        // Then the generalized form `b_ty` would be `&'?2 ?3`, where
        // `'?2` and `?3` are fresh region/type inference
        // variables. (Down below, we will relate `a_ty <: b_ty`,
        // adding constraints like `'x: '?2` and `?1 <: ?3`.)
        let Generalization { value: b_ty, needs_wf } = self.generalize(a_ty, b_vid, dir)?;
        debug!(?b_ty);
        self.infcx.inner.borrow_mut().type_variables().instantiate(b_vid, b_ty);

        if needs_wf {
            self.obligations.push(Obligation::new(
                self.tcx(),
                self.trace.cause.clone(),
                self.param_env,
                ty::Binder::dummy(ty::PredicateKind::WellFormed(b_ty.into())),
            ));
        }

        // Finally, relate `b_ty` to `a_ty`, as described in previous comment.
        //
        // FIXME(#16847): This code is non-ideal because all these subtype
        // relations wind up attributed to the same spans. We need
        // to associate causes/spans with each of the relations in
        // the stack to get this right.
        match dir {
            EqTo => self.equate(a_is_expected).relate(a_ty, b_ty),
            SubtypeOf => self.sub(a_is_expected).relate(a_ty, b_ty),
            SupertypeOf => self.sub(a_is_expected).relate_with_variance(
                ty::Contravariant,
                ty::VarianceDiagInfo::default(),
                a_ty,
                b_ty,
            ),
        }?;

        Ok(())
    }

    /// Attempts to generalize `ty` for the type variable `for_vid`.
    /// This checks for cycle -- that is, whether the type `ty`
    /// references `for_vid`. The `dir` is the "direction" for which we
    /// a performing the generalization (i.e., are we producing a type
    /// that can be used as a supertype etc).
    ///
    /// Preconditions:
    ///
    /// - `for_vid` is a "root vid"
    #[instrument(skip(self), level = "trace", ret)]
    fn generalize(
        &mut self,
        ty: Ty<'tcx>,
        for_vid: ty::TyVid,
        dir: RelationDir,
    ) -> RelateResult<'tcx, Generalization<Ty<'tcx>>> {
        // Determine the ambient variance within which `ty` appears.
        // The surrounding equation is:
        //
        //     ty [op] ty2
        //
        // where `op` is either `==`, `<:`, or `:>`. This maps quite
        // naturally.
        let ambient_variance = match dir {
            RelationDir::EqTo => ty::Invariant,
            RelationDir::SubtypeOf => ty::Covariant,
            RelationDir::SupertypeOf => ty::Contravariant,
        };

        generalize::generalize(
            self.infcx,
            &mut CombineDelegate {
                infcx: self.infcx,
                param_env: self.param_env,
                span: self.trace.span(),
            },
            ty,
            for_vid,
            ambient_variance,
        )
    }

    pub fn register_obligations(&mut self, obligations: PredicateObligations<'tcx>) {
        self.obligations.extend(obligations.into_iter());
    }

    pub fn register_predicates(&mut self, obligations: impl IntoIterator<Item: ToPredicate<'tcx>>) {
        self.obligations.extend(obligations.into_iter().map(|to_pred| {
            Obligation::new(self.infcx.tcx, self.trace.cause.clone(), self.param_env, to_pred)
        }))
    }
}

pub trait ObligationEmittingRelation<'tcx>: TypeRelation<'tcx> {
    /// Register obligations that must hold in order for this relation to hold
    fn register_obligations(&mut self, obligations: PredicateObligations<'tcx>);

    /// Register predicates that must hold in order for this relation to hold. Uses
    /// a default obligation cause, [`ObligationEmittingRelation::register_obligations`] should
    /// be used if control over the obligation causes is required.
    fn register_predicates(&mut self, obligations: impl IntoIterator<Item: ToPredicate<'tcx>>);

    /// Register an obligation that both constants must be equal to each other.
    ///
    /// If they aren't equal then the relation doesn't hold.
    fn register_const_equate_obligation(&mut self, a: ty::Const<'tcx>, b: ty::Const<'tcx>) {
        let (a, b) = if self.a_is_expected() { (a, b) } else { (b, a) };

        self.register_predicates([ty::Binder::dummy(if self.tcx().trait_solver_next() {
            ty::PredicateKind::AliasRelate(a.into(), b.into(), ty::AliasRelationDirection::Equate)
        } else {
            ty::PredicateKind::ConstEquate(a, b)
        })]);
    }

    /// Register an obligation that both types must be related to each other according to
    /// the [`ty::AliasRelationDirection`] given by [`ObligationEmittingRelation::alias_relate_direction`]
    fn register_type_relate_obligation(&mut self, a: Ty<'tcx>, b: Ty<'tcx>) {
        self.register_predicates([ty::Binder::dummy(ty::PredicateKind::AliasRelate(
            a.into(),
            b.into(),
            self.alias_relate_direction(),
        ))]);
    }

    /// Relation direction emitted for `AliasRelate` predicates, corresponding to the direction
    /// of the relation.
    fn alias_relate_direction(&self) -> ty::AliasRelationDirection;
}

fn int_unification_error<'tcx>(
    a_is_expected: bool,
    v: (ty::IntVarValue, ty::IntVarValue),
) -> TypeError<'tcx> {
    let (a, b) = v;
    TypeError::IntMismatch(ExpectedFound::new(a_is_expected, a, b))
}

fn float_unification_error<'tcx>(
    a_is_expected: bool,
    v: (ty::FloatVarValue, ty::FloatVarValue),
) -> TypeError<'tcx> {
    let (ty::FloatVarValue(a), ty::FloatVarValue(b)) = v;
    TypeError::FloatMismatch(ExpectedFound::new(a_is_expected, a, b))
}
