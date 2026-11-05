// held-out heldout_07 (CWE-78): an RxJS forkJoin over service lookups keyed by a route parameter
// HELD-OUT-TOKENS: forkJoin, switchMap
import { forkJoin, of } from 'rxjs'
import { catchError, switchMap } from 'rxjs/operators'

export class LessonPageComponent {
  public lessonKey: string
  public lessonName: string
  public isLoaded = false

  constructor (
    private readonly route: RouteState,
    private readonly lessonService: LessonService,
    private readonly notesService: NotesService
  ) {}

  init (): void {
    this.route.params.pipe(
      switchMap((params) => {
        this.lessonKey = params['lessonKey']
        this.isLoaded = false
        return forkJoin({
          lessons: this.lessonService.find({ sort: 'name' }),
          notes: this.notesService.get(this.lessonKey).pipe(
            catchError(() => of(null))
          )
        })
      })
    ).subscribe(({ lessons, notes }) => {
      const lesson = lessons.find(l => l.key === this.lessonKey)
      if (lesson) {
        this.lessonName = lesson.name
      }
      this.isLoaded = notes !== null
    })
  }
}
