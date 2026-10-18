// held-out heldout_25 (CWE-78): an RxJS forkJoin over an array of per-item update observables built in a map callback
// HELD-OUT-TOKENS: forkJoin, switchMap
import { forkJoin, of, type Observable } from 'rxjs'
import { catchError, map, switchMap, tap } from 'rxjs/operators'

export class CartService {
  mergeGuestItems (targetCartId: number): Observable<void> {
    const merged = this.guestItems().reduce((acc, item) => {
      acc.set(item.ItemId, (acc.get(item.ItemId) ?? 0) + item.quantity)
      return acc
    }, new Map<number, number>())

    if (merged.size === 0) {
      return of(void 0)
    }

    return this.find(targetCartId).pipe(
      catchError(() => of({ Items: [] })),
      switchMap((target: any) => {
        const existing = new Map<number, any>()
        ;(target.Items ?? []).forEach((item: any) => {
          existing.set(item.id, item.CartItem)
        })

        const updates = Array.from(merged.entries()).map(([itemId, quantity]) => {
          const current = existing.get(itemId)
          if (current != null) {
            return this.put(current.id, { quantity: current.quantity + quantity }).pipe(catchError(() => of(null)))
          }
          return this.save({ ItemId: itemId, CartId: targetCartId, quantity }).pipe(catchError(() => of(null)))
        })

        if (updates.length === 0) {
          return of([])
        }

        return forkJoin(updates)
      }),
      tap(() => {
        this.clearGuestItems()
      }),
      map(() => void 0)
    )
  }
}
