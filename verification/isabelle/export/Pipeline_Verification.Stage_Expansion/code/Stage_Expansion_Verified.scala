object Stage_Expansion_Verified {

abstract sealed class nat
final case class zero_nat() extends nat
final case class Suc(a : nat) extends nat

def less_nat(m : nat, x1 : nat) : Boolean = (m, x1) match {
  case (m, Suc(n)) => less_eq_nat(m, n)
  case (n, zero_nat()) => false
}

def less_eq_nat(x0 : nat, n : nat) : Boolean = (x0, n) match {
  case (Suc(m), n) => less_nat(m, n)
  case (zero_nat(), n) => true
}

trait ord[A] {
  val `Stage_Expansion_Verified.less_eq` : (A, A) => Boolean
  val `Stage_Expansion_Verified.less` : (A, A) => Boolean
}
def less_eq[A](a : A, b : A)(implicit A: ord[A]) : Boolean =
  A.`Stage_Expansion_Verified.less_eq`(a, b)
def less[A](a : A, b : A)(implicit A: ord[A]) : Boolean =
  A.`Stage_Expansion_Verified.less`(a, b)
object ord {
  implicit def `Stage_Expansion_Verified.ord_nat` : ord[nat] = new ord[nat] {
    val `Stage_Expansion_Verified.less_eq` = (a : nat, b : nat) =>
      less_eq_nat(a, b)
    val `Stage_Expansion_Verified.less` = (a : nat, b : nat) => less_nat(a, b)
  }
}

trait preorder[A] extends ord[A] {
}
object preorder {
  implicit def `Stage_Expansion_Verified.preorder_nat` : preorder[nat] = new
    preorder[nat] {
    val `Stage_Expansion_Verified.less_eq` = (a : nat, b : nat) =>
      less_eq_nat(a, b)
    val `Stage_Expansion_Verified.less` = (a : nat, b : nat) => less_nat(a, b)
  }
}

trait order[A] extends preorder[A] {
}
object order {
  implicit def `Stage_Expansion_Verified.order_nat` : order[nat] = new
    order[nat] {
    val `Stage_Expansion_Verified.less_eq` = (a : nat, b : nat) =>
      less_eq_nat(a, b)
    val `Stage_Expansion_Verified.less` = (a : nat, b : nat) => less_nat(a, b)
  }
}

trait linorder[A] extends order[A] {
}
object linorder {
  implicit def `Stage_Expansion_Verified.linorder_nat` : linorder[nat] = new
    linorder[nat] {
    val `Stage_Expansion_Verified.less_eq` = (a : nat, b : nat) =>
      less_eq_nat(a, b)
    val `Stage_Expansion_Verified.less` = (a : nat, b : nat) => less_nat(a, b)
  }
}

abstract sealed class stage
final case class Scan() extends stage
final case class Discover() extends stage
final case class Prove() extends stage

def equal_stagea(x0 : stage, x1 : stage) : Boolean = (x0, x1) match {
  case (Discover(), Prove()) => false
  case (Prove(), Discover()) => false
  case (Scan(), Prove()) => false
  case (Prove(), Scan()) => false
  case (Scan(), Discover()) => false
  case (Discover(), Scan()) => false
  case (Prove(), Prove()) => true
  case (Discover(), Discover()) => true
  case (Scan(), Scan()) => true
}

trait equal[A] {
  val `Stage_Expansion_Verified.equal` : (A, A) => Boolean
}
def equal[A](a : A, b : A)(implicit A: equal[A]) : Boolean =
  A.`Stage_Expansion_Verified.equal`(a, b)
object equal {
  implicit def `Stage_Expansion_Verified.equal_stage` : equal[stage] = new
    equal[stage] {
    val `Stage_Expansion_Verified.equal` = (a : stage, b : stage) =>
      equal_stagea(a, b)
  }
}

abstract sealed class num
final case class One() extends num
final case class Bit0(a : num) extends num
final case class Bit1(a : num) extends num

def id[A] : A => A = ((x : A) => x)

def eq[A : equal](a : A, b : A) : Boolean = equal[A](a, b)

def comp[A, B, C](f : A => B, g : C => A) : C => B = ((x : C) => f(g(x)))

def maps[A, B](f : A => List[B], x1 : List[A]) : List[B] = (f, x1) match {
  case (f, Nil) => Nil
  case (f, x :: xs) => f(x) ++ maps[A, B](f, xs)
}

def foldr[A, B](f : A => B => B, x1 : List[A]) : B => B = (f, x1) match {
  case (f, Nil) => id[B]
  case (f, x :: xs) => comp[B, B, B](f(x), foldr[A, B](f, xs))
}

def member[A : equal](x0 : List[A], y : A) : Boolean = (x0, y) match {
  case (Nil, y) => false
  case (x :: xs, y) => eq[A](x, y) || member[A](xs, y)
}

def remdups[A : equal](x0 : List[A]) : List[A] = x0 match {
  case Nil => Nil
  case x :: xs =>
    (member[A](xs, x) match { case true => remdups[A](xs)
      case false => x :: remdups[A](xs) })
}

def plus_nat(x0 : nat, n : nat) : nat = (x0, n) match {
  case (Suc(m), n) => plus_nat(m, Suc(n))
  case (zero_nat(), n) => n
}

def one_nat : nat = Suc(zero_nat())

def nat_of_num(x0 : num) : nat = x0 match {
  case Bit1(n) => {
                    val m = nat_of_num(n) : nat;
                    Suc(plus_nat(m, m))
                  }
  case Bit0(n) => {
                    val m = nat_of_num(n) : nat;
                    plus_nat(m, m)
                  }
  case One() => one_nat
}

def prereqs(x0 : stage, uu : Boolean) : List[stage] = (x0, uu) match {
  case (Scan(), uu) => Nil
  case (Discover(), true) => List(Scan())
  case (Discover(), false) => Nil
  case (Prove(), uv) => List(Scan(), Discover())
}

def stage_rank(x0 : stage) : nat = x0 match {
  case Scan() => zero_nat()
  case Discover() => one_nat
  case Prove() => nat_of_num(Bit0(One()))
}

def insort_key[A, B : linorder](f : A => B, x : A, xa2 : List[A]) : List[A] =
  (f, x, xa2) match {
  case (f, x, Nil) => List(x)
  case (f, x, y :: ys) =>
    (less_eq[B](f(x), f(y)) match { case true => x :: y :: ys
      case false => y :: insort_key[A, B](f, x, ys) })
}

def sort_key[A, B : linorder](f : A => B, xs : List[A]) : List[A] =
  (foldr[A, List[A]](((a : A) => (b : List[A]) => insort_key[A, B](f, a, b)),
                      xs)).apply(Nil)

def expand_stages(requested : List[stage], has_source : Boolean) : List[stage] =
  sort_key[stage,
            nat](((a : stage) => stage_rank(a)),
                  remdups[stage](maps[stage,
                                       stage](((s : stage) =>
        prereqs(s, has_source) ++ List(s)),
       requested)))

} /* object Stage_Expansion_Verified */
