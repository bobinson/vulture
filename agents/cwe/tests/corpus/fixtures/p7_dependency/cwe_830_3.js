export function loadWidget(target) {
  const node = document.createElement('script');
  node.async = true;
  node.src = "//widgets.example.net/embed/v3/widget.js";
  target.appendChild(node);
  return node;
}
