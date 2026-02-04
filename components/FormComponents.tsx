import React, { ChangeEvent } from 'react';

interface FormFieldProps {
  label: string;
  children: React.ReactNode;
}

export const FormField: React.FC<FormFieldProps> = ({ label, children }) => (
  <div className="space-y-2">
    <label className="block text-sm font-medium text-gray-900">{label}</label>
    {children}
  </div>
);

interface TextInputProps {
  name: string;
  value: string;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  type?: string;
  required?: boolean;  // Add this line
}

export const TextInput: React.FC<TextInputProps> = ({ 
  name, 
  value, 
  onChange, 
  placeholder,
  type = 'text',
  required = false  // Add this line
}) => (
  <input
    type={type}
    name={name}
    value={value}
    onChange={onChange}
    placeholder={placeholder}
    required={required}  // Add this line
    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-gray-900 placeholder-gray-500"
  />
);

interface RadioGroupProps {
  name: string;
  options: { label: string; value: string; }[];
  value: string;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
}

export const RadioGroup: React.FC<RadioGroupProps> = ({ name, options, value, onChange }) => (
  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
    {options.map((option) => (
      <label key={option.value} className="relative flex items-center">
        <input
          type="radio"
          name={name}
          value={option.value}
          checked={value === option.value}
          onChange={onChange}
          className="sr-only peer"
        />
        <div className="w-full p-2.5 text-sm text-gray-900 bg-white border rounded-lg peer-checked:border-blue-500 peer-checked:bg-blue-50 cursor-pointer">
          {option.label}
        </div>
      </label>
    ))}
  </div>
);

interface CheckboxGroupProps {
  section: string;
  options: { label: string; value: string; }[];
  values: Record<string, boolean>;
  onChange: (section: string, field: string) => void;
}

export const CheckboxGroup: React.FC<CheckboxGroupProps> = ({ section, options, values, onChange }) => (
  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
    {options.map((option) => (
      <label key={option.value} className="relative flex items-center p-2 rounded-lg border hover:bg-gray-50">
        <input
          type="checkbox"
          checked={values[option.value]}
          onChange={() => onChange(section, option.value)}
          className="w-5 h-5 text-blue-500 border-gray-300 rounded focus:ring-blue-500"
        />
        <span className="ml-2 text-sm text-gray-900">{option.label}</span>
      </label>
    ))}
  </div>
);