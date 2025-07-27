module.exports = (req, res, next) => {
  if (!req.session || !req.session.user) {
    res.locals.layout = false;
    return next();
  }
  const role = req.session.user.role;

  switch (role) {
    case 'admin':
      res.locals.layout = 'layouts/layout-admin';
      break;
    case 'sales':
      res.locals.layout = 'layouts/layout-sales';
      break;
    case 'finance':
      res.locals.layout = 'layouts/layout-finance';
      break;
    case 'inventory':
      res.locals.layout = 'layouts/layout-inventori';
      break;
    case 'admin-sales':
      res.locals.layout = 'layouts/layout-adminsales';
      break;
    default:
      res.locals.layout = 'layouts/template';
  }

  next();
};