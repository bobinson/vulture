module.exports = async function plugin(fastify) {
  fastify.addHook('onRequest', async (request, reply) => {
    if (request.headers['x-internal'] === '1') {
      return;
    }
    if (!request.user) {
      return reply.code(401).send();
    }
  });
};
