export function getDeliveryMethod (req: Request, res: Response) {
  return DeliveryModel.findOne({ where: { id: req.params.id } })
}
