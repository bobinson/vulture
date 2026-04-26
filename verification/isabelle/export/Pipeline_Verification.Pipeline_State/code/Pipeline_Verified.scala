object Pipeline_Verified {

abstract sealed class pipeline_status
final case class Pending() extends pipeline_status
final case class ScanRunning() extends pipeline_status
final case class DiscoverRunning() extends pipeline_status
final case class ProveRunning() extends pipeline_status
final case class Completed() extends pipeline_status
final case class Failed() extends pipeline_status

def equal_pipeline_statusa(x0 : pipeline_status, x1 : pipeline_status) : Boolean
  =
  (x0, x1) match {
  case (Completed(), Failed()) => false
  case (Failed(), Completed()) => false
  case (ProveRunning(), Failed()) => false
  case (Failed(), ProveRunning()) => false
  case (ProveRunning(), Completed()) => false
  case (Completed(), ProveRunning()) => false
  case (DiscoverRunning(), Failed()) => false
  case (Failed(), DiscoverRunning()) => false
  case (DiscoverRunning(), Completed()) => false
  case (Completed(), DiscoverRunning()) => false
  case (DiscoverRunning(), ProveRunning()) => false
  case (ProveRunning(), DiscoverRunning()) => false
  case (ScanRunning(), Failed()) => false
  case (Failed(), ScanRunning()) => false
  case (ScanRunning(), Completed()) => false
  case (Completed(), ScanRunning()) => false
  case (ScanRunning(), ProveRunning()) => false
  case (ProveRunning(), ScanRunning()) => false
  case (ScanRunning(), DiscoverRunning()) => false
  case (DiscoverRunning(), ScanRunning()) => false
  case (Pending(), Failed()) => false
  case (Failed(), Pending()) => false
  case (Pending(), Completed()) => false
  case (Completed(), Pending()) => false
  case (Pending(), ProveRunning()) => false
  case (ProveRunning(), Pending()) => false
  case (Pending(), DiscoverRunning()) => false
  case (DiscoverRunning(), Pending()) => false
  case (Pending(), ScanRunning()) => false
  case (ScanRunning(), Pending()) => false
  case (Failed(), Failed()) => true
  case (Completed(), Completed()) => true
  case (ProveRunning(), ProveRunning()) => true
  case (DiscoverRunning(), DiscoverRunning()) => true
  case (ScanRunning(), ScanRunning()) => true
  case (Pending(), Pending()) => true
}

trait equal[A] {
  val `Pipeline_Verified.equal` : (A, A) => Boolean
}
def equal[A](a : A, b : A)(implicit A: equal[A]) : Boolean =
  A.`Pipeline_Verified.equal`(a, b)
object equal {
  implicit def
    `Pipeline_Verified.equal_pipeline_status` : equal[pipeline_status] = new
    equal[pipeline_status] {
    val `Pipeline_Verified.equal` = (a : pipeline_status, b : pipeline_status)
      => equal_pipeline_statusa(a, b)
  }
}

abstract sealed class nat
final case class zero_nat() extends nat
final case class Suc(a : nat) extends nat

abstract sealed class set[A]
final case class seta[A](a : List[A]) extends set[A]
final case class coset[A](a : List[A]) extends set[A]

abstract sealed class stage
final case class Scan() extends stage
final case class Discover() extends stage
final case class Prove() extends stage

abstract sealed class audit_outcome
final case class AuditCompleted() extends audit_outcome
final case class AuditFailed() extends audit_outcome

abstract sealed class pipeline_ext[A]
final case class pipeline_exta[A](a : pipeline_status, b : List[stage], c : nat,
                                   d : A)
  extends pipeline_ext[A]

def eq[A : equal](a : A, b : A) : Boolean = equal[A](a, b)

def nth[A](x0 : List[A], x1 : nat) : A = (x0, x1) match {
  case (x :: xs, Suc(n)) => nth[A](xs, n)
  case (x :: xs, zero_nat()) => x
}

def removeAll[A : equal](x : A, xa1 : List[A]) : List[A] = (x, xa1) match {
  case (x, Nil) => Nil
  case (x, y :: xs) =>
    (eq[A](x, y) match { case true => removeAll[A](x, xs)
      case false => y :: removeAll[A](x, xs) })
}

def membera[A : equal](x0 : List[A], y : A) : Boolean = (x0, y) match {
  case (Nil, y) => false
  case (x :: xs, y) => eq[A](x, y) || membera[A](xs, y)
}

def inserta[A : equal](x : A, xs : List[A]) : List[A] =
  (membera[A](xs, x) match { case true => xs case false => x :: xs })

def insert[A : equal](x : A, xa1 : set[A]) : set[A] = (x, xa1) match {
  case (x, coset(xs)) => coset[A](removeAll[A](x, xs))
  case (x, seta(xs)) => seta[A](inserta[A](x, xs))
}

def member[A : equal](x : A, xa1 : set[A]) : Boolean = (x, xa1) match {
  case (x, coset(xs)) => ! (membera[A](xs, x))
  case (x, seta(xs)) => membera[A](xs, x)
}

def gen_length[A](n : nat, x1 : List[A]) : nat = (n, x1) match {
  case (n, x :: xs) => gen_length[A](Suc(n), xs)
  case (n, Nil) => n
}

def p_status_update[A](p_statusa : pipeline_status => pipeline_status,
                        x1 : pipeline_ext[A]) : pipeline_ext[A]
  =
  (p_statusa, x1) match {
  case (p_statusa, pipeline_exta(p_status, p_stages, p_index, more)) =>
    pipeline_exta[A](p_statusa(p_status), p_stages, p_index, more)
}

def p_index_update[A](p_indexa : nat => nat,
                       x1 : pipeline_ext[A]) : pipeline_ext[A]
  =
  (p_indexa, x1) match {
  case (p_indexa, pipeline_exta(p_status, p_stages, p_index, more)) =>
    pipeline_exta[A](p_status, p_stages, p_indexa(p_index), more)
}

def p_status[A](x0 : pipeline_ext[A]) : pipeline_status = x0 match {
  case pipeline_exta(p_status, p_stages, p_index, more) => p_status
}

def p_stages[A](x0 : pipeline_ext[A]) : List[stage] = x0 match {
  case pipeline_exta(p_status, p_stages, p_index, more) => p_stages
}

def stage_to_running(x0 : stage) : pipeline_status = x0 match {
  case Scan() => ScanRunning()
  case Discover() => DiscoverRunning()
  case Prove() => ProveRunning()
}

def p_index[A](x0 : pipeline_ext[A]) : nat = x0 match {
  case pipeline_exta(p_status, p_stages, p_index, more) => p_index
}

def size_list[A] : (List[A]) => nat =
  ((a : List[A]) => gen_length[A](zero_nat(), a))

def less_eq_nat(x0 : nat, n : nat) : Boolean = (x0, n) match {
  case (Suc(m), n) => less_nat(m, n)
  case (zero_nat(), n) => true
}

def less_nat(m : nat, x1 : nat) : Boolean = (m, x1) match {
  case (m, Suc(n)) => less_eq_nat(m, n)
  case (n, zero_nat()) => false
}

def bot_set[A] : set[A] = seta[A](Nil)

def advance(p : pipeline_ext[Unit],
             outcome : audit_outcome) : pipeline_ext[Unit]
  =
  (member[pipeline_status](p_status[Unit](p),
                            insert[pipeline_status](Completed(),
             insert[pipeline_status](Failed(),
                                      insert[pipeline_status](Pending(),
                       bot_set[pipeline_status])))) match {
    case true => p
    case false => (outcome match {
                     case AuditCompleted() =>
                       {
                         val next_idx = Suc(p_index[Unit](p)) : nat;
                         (less_nat(next_idx,
                                    size_list[stage].apply(p_stages[Unit](p))) match {
                           case true => p_index_update[Unit](((_ : nat) =>
                       next_idx),
                      p_status_update[Unit](((_ : pipeline_status) =>
      stage_to_running(nth[stage](p_stages[Unit](p), next_idx))),
     p))
                           case false => p_status_update[Unit](((_ : pipeline_status)
                          =>
                         Completed()),
                        p)
                           })
                       }
                     case AuditFailed() =>
                       p_status_update[Unit](((_ : pipeline_status) =>
       Failed()),
      p)
                   })
    })

} /* object Pipeline_Verified */
