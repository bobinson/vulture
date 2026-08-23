export function loadThumbnail(target) {
  const node = document.createElement('img');
  node.loading = "lazy";
  node.src = "//images.example.net/thumbs/v3/cover.png";
  target.appendChild(node);
  return node;
}
