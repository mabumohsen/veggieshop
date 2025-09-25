noClasses().that()
  .resideInAPackage("io.veggieshop.platform.messaging..")
  .should().beAnnotatedWith(org.springframework.stereotype.Component.class)
  .orShould().beAnnotatedWith(org.springframework.context.annotation.Configuration.class)
  .orShould().beAnnotatedWith(org.springframework.beans.factory.annotation.Autowired.class)
  .orShould().beAnnotatedWith(org.springframework.scheduling.annotation.Scheduled.class)
  .orShould().beAnnotatedWith(org.springframework.beans.factory.annotation.Value.class)
  .orShould().beAnnotatedWith(jakarta.annotation.PreDestroy.class);
