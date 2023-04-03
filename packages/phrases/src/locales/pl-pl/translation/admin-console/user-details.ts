const user_details = {
  page_title: 'Szczegóły użytkownika',
  back_to_users: 'Powrót do zarządzania użytkownikami',
  created_title: 'Ten użytkownik został pomyślnie utworzony',
  created_guide: 'Możesz wysłać następujące informacje o logowaniu do użytkownika',
  created_username: 'Nazwa użytkownika:',
  created_password: 'Hasło:',
  menu_delete: 'Usuń',
  delete_description: 'Tej akcji nie można cofnąć. Usunie to użytkownika na stałe.',
  deleted: 'Użytkownik został pomyślnie usunięty',
  reset_password: {
    reset_password: 'Zresetuj hasło',
    title: 'Czy na pewno chcesz zresetować hasło?',
    content: 'Tej akcji nie można cofnąć. To zresetuje informacje o logowaniu użytkownika.',
    congratulations: 'Ten użytkownik został zresetowany',
    new_password: 'Nowe hasło:',
  },
  tab_settings: 'Ustawienia',
  tab_roles: 'Role',
  tab_logs: 'Logi użytkownika',
  settings: 'Ustawienia',
  settings_description:
    'Każdy użytkownik ma profil zawierający wszystkie informacje o użytkowniku. Składa się on z podstawowych danych, tożsamości społecznościowych i niestandardowych danych.',
  field_email: 'E-mail podstawowy',
  field_phone: 'Telefon podstawowy',
  field_username: 'Nazwa użytkownika',
  field_name: 'Imię i nazwisko',
  field_avatar: 'Adres URL obrazka awatara',
  field_avatar_placeholder: 'https://twoja.domena/cdn/avatar.png',
  field_custom_data: 'Dane niestandardowe',
  field_custom_data_tip:
    'Dodatkowe informacje o użytkowniku niewymienione jako właściwości predefiniowane, takie jak preferowany przez użytkownika kolor i język.',
  field_connectors: 'Połączenia społecznościowe',
  custom_data_invalid: 'Nieprawidłowe dane niestandardowe JSON',
  connectors: {
    connectors: 'Połączenia',
    user_id: 'Identyfikator użytkownika',
    remove: 'Usuń',
    not_connected: 'Użytkownik nie jest połączony z żadnym połączeniem społecznościowym',
    deletion_confirmation: 'Usuwasz istniejącą tożsamość <name/>. Czy na pewno chcesz to zrobić?',
  },
  suspended: 'Zawieszony',
  roles: {
    name_column: 'Rola',
    description_column: 'Opis',
    assign_button: 'Przypisz role',
    delete_description:
      'Ta akcja usunie tę rolę z tego użytkownika. Rola nadal będzie istnieć, ale nie będzie już przypisana do tego użytkownika.',
    deleted: '{{name}} został usunięty z tego użytkownika.',
    assign_title: 'Przypisz role dla {{name}}',
    assign_subtitle: 'Autoryzuj {{name}} jedną lub wiele ról',
    assign_role_field: 'Przypisz role',
    role_search_placeholder: 'Szukaj po nazwie roli',
    added_text: '{{value, number}} dodanych',
    assigned_user_count: '{{value, number}} użytkowników',
    confirm_assign: 'Przypisz role',
    role_assigned: 'Pomyślnie przypisano rolę(y)',
    search: 'Szukaj po nazwie roli, opisie lub ID',
    empty: 'Brak dostępnej roli',
  },
};

export default user_details;
