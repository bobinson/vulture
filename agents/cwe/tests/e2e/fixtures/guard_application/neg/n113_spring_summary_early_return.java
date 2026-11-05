@GetMapping("/users/{id}")
public Object get(@PathVariable Long id, HttpServletRequest request) {
    if ("summary".equals(request.getParameter("mode"))) {
        return new UserSummary(repo.find(id));
    }
    if (request.getUserPrincipal() == null) {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
    return new UserDetails(repo.find(id));
}
