import { error } from './catalog'
export function h(req, res) {
  // EXPECT-NEXT: finding  known-gap imported error const
  res.status(400).json(error)
}
